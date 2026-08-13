// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
)

// BuildUpstreamFrame serializes one normalized report and applies the class
// 309 upstream tag-control operation. A nil frame is returned for an IGMPv1
// leave because that protocol has no leave message.
func BuildUpstreamFrame(report UpstreamReport) ([]byte, error) {
	group := report.Group.Group
	if !group.IsValid() || !group.IsMulticast() {
		return nil, fmt.Errorf("invalid upstream multicast group %s", group)
	}
	if !report.Group.Source.IsValid() || report.Group.Source.BitLen() != group.BitLen() ||
		!report.Group.Client.IsValid() || report.Group.Client.BitLen() != group.BitLen() {
		return nil, fmt.Errorf("upstream multicast source or client address has the wrong family")
	}

	var payload []byte
	var etherType uint16
	var destination [6]byte
	var err error
	if group.Is4() {
		if report.Profile.IGMPVersion < 1 || report.Profile.IGMPVersion > 3 {
			return nil, fmt.Errorf("profile %d does not select an IGMP version", report.Profile.EntityID)
		}
		payload, err = buildIGMPPacket(report)
		if err != nil || payload == nil {
			return payload, err
		}
		etherType = 0x0800
		destination = ipv4MulticastMAC(ipv4Destination(report))
	} else {
		if report.Profile.IGMPVersion != 16 && report.Profile.IGMPVersion != 17 {
			return nil, fmt.Errorf("profile %d does not select an MLD version", report.Profile.EntityID)
		}
		payload, err = buildMLDPacket(report)
		if err != nil {
			return nil, err
		}
		etherType = 0x86dd
		destination = ipv6MulticastMAC(ipv6Destination(report))
	}

	tags, err := upstreamTags(report.Tags, report.Profile.UpstreamTagControl,
		report.Profile.UpstreamTCI)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 14+len(tags)*4+len(payload))
	copy(frame[0:6], destination[:])
	copy(frame[6:12], report.SourceMAC[:])
	offset := 12
	for _, tag := range tags {
		binary.BigEndian.PutUint16(frame[offset:offset+2], tag.TPID)
		binary.BigEndian.PutUint16(frame[offset+2:offset+4], tag.TCI)
		offset += 4
	}
	binary.BigEndian.PutUint16(frame[offset:offset+2], etherType)
	copy(frame[offset+2:], payload)
	return frame, nil
}

func upstreamTags(original []VLANTag, control uint8, tci uint16) ([]VLANTag, error) {
	if control > 3 {
		return nil, fmt.Errorf("invalid upstream tag control %d", control)
	}
	tags := cloneVLANTags(original)
	switch control {
	case 0:
		return tags, nil
	case 1:
		return append([]VLANTag{{TPID: 0x8100, TCI: tci}}, tags...), nil
	case 2:
		if len(tags) == 0 {
			return []VLANTag{{TPID: 0x8100, TCI: tci}}, nil
		}
		tags[0].TCI = tci
		return tags, nil
	case 3:
		if len(tags) == 0 {
			return []VLANTag{{TPID: 0x8100, TCI: tci}}, nil
		}
		tags[0].TCI = tags[0].TCI&0xf000 | tci&0x0fff
		return tags, nil
	default:
		panic("unreachable")
	}
}

func buildIGMPPacket(report UpstreamReport) ([]byte, error) {
	version := report.Profile.IGMPVersion
	group := report.Group.Group.As4()
	source := report.Group.Source
	wildcard := source == netip.IPv4Unspecified()
	var igmp []byte
	var destination [4]byte
	switch version {
	case 1:
		if !report.Join {
			return nil, nil
		}
		igmp = make([]byte, 8)
		igmp[0] = 0x12
		destination = group
	case 2:
		igmp = make([]byte, 8)
		if report.Join {
			igmp[0] = 0x16
			destination = group
		} else {
			igmp[0] = 0x17
			destination = [4]byte{224, 0, 0, 2}
		}
	case 3:
		if len(report.Group.ExcludedSources) > math.MaxUint16 {
			return nil, fmt.Errorf("too many IGMP exclusion sources: %d", len(report.Group.ExcludedSources))
		}
		included := report.Group.IncludedSources
		if len(included) == 0 && !wildcard {
			included = []netip.Addr{source}
		}
		if len(included) > math.MaxUint16 {
			return nil, fmt.Errorf("too many IGMP inclusion sources: %d", len(included))
		}
		igmp = make([]byte, 16)
		igmp[0] = 0x22
		binary.BigEndian.PutUint16(igmp[6:8], 1)
		if report.Join {
			if wildcard {
				igmp[8] = byte(ChangeToExcludeMode)
				binary.BigEndian.PutUint16(igmp[10:12], uint16(len(report.Group.ExcludedSources)))
				for _, excluded := range report.Group.ExcludedSources {
					if !excluded.Is4() {
						return nil, fmt.Errorf("IGMP exclusion source %s is not IPv4", excluded)
					}
					igmp = append(igmp, excluded.AsSlice()...)
				}
			} else {
				igmp[8] = byte(ChangeToIncludeMode)
				binary.BigEndian.PutUint16(igmp[10:12], uint16(len(included)))
				for _, includedSource := range included {
					if !includedSource.Is4() {
						return nil, fmt.Errorf("IGMP inclusion source %s is not IPv4", includedSource)
					}
					igmp = append(igmp, includedSource.AsSlice()...)
				}
			}
		} else if wildcard {
			igmp[8] = byte(ChangeToIncludeMode)
		} else {
			igmp[8] = byte(BlockOldSources)
			binary.BigEndian.PutUint16(igmp[10:12], 1)
			igmp = append(igmp, source.AsSlice()...)
		}
		copy(igmp[12:16], group[:])
		destination = [4]byte{224, 0, 0, 22}
	default:
		return nil, fmt.Errorf("invalid IGMP version %d", version)
	}
	if version != 3 {
		copy(igmp[4:8], group[:])
	}
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))

	// RFC 2236/3376 require TTL 1 and the IPv4 Router Alert option.
	ip := make([]byte, 24+len(igmp))
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8], ip[9] = 1, 2
	copy(ip[12:16], report.Group.Client.AsSlice())
	copy(ip[16:20], destination[:])
	copy(ip[20:24], []byte{0x94, 0x04, 0x00, 0x00})
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:24]))
	copy(ip[24:], igmp)
	return ip, nil
}

func buildMLDPacket(report UpstreamReport) ([]byte, error) {
	version := report.Profile.IGMPVersion
	group := report.Group.Group.As16()
	sourceAddress := report.Group.Source
	wildcard := sourceAddress == netip.IPv6Unspecified()
	var icmp []byte
	var destination [16]byte
	switch version {
	case 16:
		icmp = make([]byte, 24)
		if report.Join {
			icmp[0] = 131
			destination = group
		} else {
			icmp[0] = 132
			destination = netip.MustParseAddr("ff02::2").As16()
		}
		copy(icmp[8:24], group[:])
	case 17:
		if len(report.Group.ExcludedSources) > math.MaxUint16 {
			return nil, fmt.Errorf("too many MLD exclusion sources: %d", len(report.Group.ExcludedSources))
		}
		included := report.Group.IncludedSources
		if len(included) == 0 && !wildcard {
			included = []netip.Addr{sourceAddress}
		}
		if len(included) > math.MaxUint16 {
			return nil, fmt.Errorf("too many MLD inclusion sources: %d", len(included))
		}
		icmp = make([]byte, 28)
		icmp[0] = 143
		binary.BigEndian.PutUint16(icmp[6:8], 1)
		if report.Join {
			if wildcard {
				icmp[8] = byte(ChangeToExcludeMode)
				binary.BigEndian.PutUint16(icmp[10:12], uint16(len(report.Group.ExcludedSources)))
				for _, excluded := range report.Group.ExcludedSources {
					if !excluded.Is6() || excluded.Is4In6() {
						return nil, fmt.Errorf("MLD exclusion source %s is not IPv6", excluded)
					}
					icmp = append(icmp, excluded.AsSlice()...)
				}
			} else {
				icmp[8] = byte(ChangeToIncludeMode)
				binary.BigEndian.PutUint16(icmp[10:12], uint16(len(included)))
				for _, includedSource := range included {
					if !includedSource.Is6() || includedSource.Is4In6() {
						return nil, fmt.Errorf("MLD inclusion source %s is not IPv6", includedSource)
					}
					icmp = append(icmp, includedSource.AsSlice()...)
				}
			}
		} else if wildcard {
			icmp[8] = byte(ChangeToIncludeMode)
		} else {
			icmp[8] = byte(BlockOldSources)
			binary.BigEndian.PutUint16(icmp[10:12], 1)
			icmp = append(icmp, sourceAddress.AsSlice()...)
		}
		copy(icmp[12:28], group[:])
		destination = netip.MustParseAddr("ff02::16").As16()
	default:
		return nil, fmt.Errorf("invalid MLD version %d", version)
	}
	source := report.Group.Client.As16()
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(source, destination, icmp))

	// MLD requires an IPv6 hop-by-hop Router Alert and hop limit 1.
	ip := make([]byte, 48+len(icmp))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(icmp)))
	ip[6], ip[7] = 0, 1
	copy(ip[8:24], source[:])
	copy(ip[24:40], destination[:])
	copy(ip[40:48], []byte{58, 0, 5, 2, 0, 0, 1, 0})
	copy(ip[48:], icmp)
	return ip, nil
}

func ipv4Destination(report UpstreamReport) netip.Addr {
	if report.Profile.IGMPVersion == 3 {
		return netip.MustParseAddr("224.0.0.22")
	}
	if !report.Join && report.Profile.IGMPVersion == 2 {
		return netip.MustParseAddr("224.0.0.2")
	}
	return report.Group.Group
}

func ipv6Destination(report UpstreamReport) netip.Addr {
	if report.Profile.IGMPVersion == 17 {
		return netip.MustParseAddr("ff02::16")
	}
	if !report.Join {
		return netip.MustParseAddr("ff02::2")
	}
	return report.Group.Group
}

func ipv4MulticastMAC(address netip.Addr) [6]byte {
	value := address.As4()
	return [6]byte{0x01, 0x00, 0x5e, value[1] & 0x7f, value[2], value[3]}
}

func ipv6MulticastMAC(address netip.Addr) [6]byte {
	value := address.As16()
	return [6]byte{0x33, 0x33, value[12], value[13], value[14], value[15]}
}

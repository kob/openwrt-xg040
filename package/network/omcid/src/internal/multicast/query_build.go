// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"time"
)

// DownstreamQuery describes a proxy-generated general or group-specific
// membership query. An unspecified Group selects a general query; Source is
// populated only for an IGMPv3/MLDv2 group-and-source-specific query.
type DownstreamQuery struct {
	Subscriber Subscriber
	Attachment Attachment
	Profile    Profile
	Group      netip.Addr
	Source     netip.Addr
	Tags       []VLANTag
}

// BuildDownstreamQueryFrame serializes a query for transmission toward one
// UNI. Tags are already in their UNI-side representation.
func BuildDownstreamQueryFrame(query DownstreamQuery, sourceMAC [6]byte) ([]byte, error) {
	version := query.Profile.IGMPVersion
	ipv4 := version >= 1 && version <= 3
	if !ipv4 && version != 16 && version != 17 {
		return nil, fmt.Errorf("profile %d has invalid query protocol version %d",
			query.Profile.EntityID, version)
	}
	if query.Group.IsValid() {
		if !query.Group.IsMulticast() || query.Group.Is4() != ipv4 {
			return nil, fmt.Errorf("invalid downstream query group %s", query.Group)
		}
	}
	if query.Source.IsValid() && !query.Source.IsUnspecified() {
		if !query.Group.IsValid() || query.Source.Is4() != ipv4 {
			return nil, fmt.Errorf("invalid downstream query source %s", query.Source)
		}
		if version != 3 && version != 17 {
			return nil, fmt.Errorf("protocol version %d cannot encode a source-specific query", version)
		}
	}
	if len(query.Tags) > 2 {
		return nil, fmt.Errorf("downstream query has more than two VLAN tags")
	}
	for _, tag := range query.Tags {
		if tag.TPID != 0x8100 && tag.TPID != 0x88a8 && tag.TPID != 0x9100 {
			return nil, fmt.Errorf("downstream query has invalid VLAN TPID %#x", tag.TPID)
		}
	}

	var packet []byte
	var etherType uint16
	var destination [6]byte
	if ipv4 {
		packet = buildIGMPQuery(query)
		etherType = 0x0800
		address := netip.MustParseAddr("224.0.0.1")
		if query.Group.IsValid() {
			address = query.Group
		}
		destination = ipv4MulticastMAC(address)
	} else {
		packet = buildMLDQuery(query)
		etherType = 0x86dd
		address := netip.MustParseAddr("ff02::1")
		if query.Group.IsValid() {
			address = query.Group
		}
		destination = ipv6MulticastMAC(address)
	}

	frame := make([]byte, 14+len(query.Tags)*4+len(packet))
	copy(frame[0:6], destination[:])
	copy(frame[6:12], sourceMAC[:])
	offset := 12
	for _, tag := range query.Tags {
		binary.BigEndian.PutUint16(frame[offset:offset+2], tag.TPID)
		binary.BigEndian.PutUint16(frame[offset+2:offset+4], tag.TCI)
		offset += 4
	}
	binary.BigEndian.PutUint16(frame[offset:offset+2], etherType)
	copy(frame[offset+2:], packet)
	return frame, nil
}

func buildIGMPQuery(query DownstreamQuery) []byte {
	version := query.Profile.IGMPVersion
	length := 8
	if version == 3 {
		length = 12
		if query.Source.IsValid() && !query.Source.IsUnspecified() {
			length += 4
		}
	}
	igmp := make([]byte, length)
	igmp[0] = 0x11
	response := queryResponseDeciseconds(query)
	if version == 2 {
		igmp[1] = byte(min(response, uint32(math.MaxUint8)))
	} else if version == 3 {
		igmp[1] = encodeFloating8(response)
	}
	if query.Group.IsValid() {
		group := query.Group.As4()
		copy(igmp[4:8], group[:])
	}
	if version == 3 {
		robustness := effectiveRobustness(query.Profile)
		if robustness <= 7 {
			igmp[8] = robustness
		}
		igmp[9] = encodeFloating8(effectiveQueryInterval(query.Profile))
		if query.Source.IsValid() && !query.Source.IsUnspecified() {
			binary.BigEndian.PutUint16(igmp[10:12], 1)
			copy(igmp[12:16], query.Source.AsSlice())
		}
	}
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))

	destination := netip.MustParseAddr("224.0.0.1").As4()
	if query.Group.IsValid() {
		destination = query.Group.As4()
	}
	ip := make([]byte, 24+len(igmp))
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8], ip[9] = 1, 2
	binary.BigEndian.PutUint32(ip[12:16], query.Profile.QuerierIPAddress)
	copy(ip[16:20], destination[:])
	copy(ip[20:24], []byte{0x94, 0x04, 0x00, 0x00})
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:24]))
	copy(ip[24:], igmp)
	return ip
}

func buildMLDQuery(query DownstreamQuery) []byte {
	version := query.Profile.IGMPVersion
	length := 24
	if version == 17 {
		length = 28
		if query.Source.IsValid() && !query.Source.IsUnspecified() {
			length += 16
		}
	}
	icmp := make([]byte, length)
	icmp[0] = 130
	responseMilliseconds := uint64(queryResponseDeciseconds(query)) * 100
	if version == 16 {
		binary.BigEndian.PutUint16(icmp[4:6], uint16(min(responseMilliseconds, uint64(math.MaxUint16))))
	} else {
		binary.BigEndian.PutUint16(icmp[4:6], encodeFloating16(responseMilliseconds))
	}
	if query.Group.IsValid() {
		group := query.Group.As16()
		copy(icmp[8:24], group[:])
	}
	if version == 17 {
		robustness := effectiveRobustness(query.Profile)
		if robustness <= 7 {
			icmp[24] = robustness
		}
		icmp[25] = encodeFloating8(effectiveQueryInterval(query.Profile))
		if query.Source.IsValid() && !query.Source.IsUnspecified() {
			binary.BigEndian.PutUint16(icmp[26:28], 1)
			copy(icmp[28:44], query.Source.AsSlice())
		}
	}

	destination := netip.MustParseAddr("ff02::1").As16()
	if query.Group.IsValid() {
		destination = query.Group.As16()
	}
	var source [16]byte
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(source, destination, icmp))
	ip := make([]byte, 48+len(icmp))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(icmp)))
	ip[6], ip[7] = 0, 1
	copy(ip[24:40], destination[:])
	copy(ip[40:48], []byte{58, 0, 5, 2, 0, 0, 1, 0})
	copy(ip[48:], icmp)
	return ip
}

func effectiveRobustness(profile Profile) uint8 {
	if profile.Robustness == 0 {
		return 2
	}
	return profile.Robustness
}

func effectiveQueryInterval(profile Profile) uint32 {
	if profile.QueryInterval == 0 {
		return 125
	}
	return profile.QueryInterval
}

func effectiveQueryResponse(profile Profile) uint32 {
	if profile.QueryMaxResponseTime == 0 {
		return 100
	}
	return profile.QueryMaxResponseTime
}

func effectiveLastMemberInterval(profile Profile) time.Duration {
	value := profile.LastMemberQueryInterval
	if value == 0 {
		value = 10
	}
	return decisecondsDuration(uint64(value))
}

func queryResponseDeciseconds(query DownstreamQuery) uint32 {
	if query.Group.IsValid() {
		if query.Profile.LastMemberQueryInterval == 0 {
			return 10
		}
		return query.Profile.LastMemberQueryInterval
	}
	return effectiveQueryResponse(query.Profile)
}

func secondsDuration(value uint64) time.Duration {
	if value > uint64(math.MaxInt64/int64(time.Second)) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(value) * time.Second
}

func decisecondsDuration(value uint64) time.Duration {
	const unit = 100 * time.Millisecond
	if value > uint64(math.MaxInt64/int64(unit)) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(value) * unit
}

func membershipInterval(profile Profile) time.Duration {
	seconds := uint64(effectiveRobustness(profile)) * uint64(effectiveQueryInterval(profile))
	first := secondsDuration(seconds)
	second := decisecondsDuration(uint64(effectiveQueryResponse(profile)))
	if first > time.Duration(math.MaxInt64)-second {
		return time.Duration(math.MaxInt64)
	}
	return first + second
}

func encodeFloating8(value uint32) byte {
	if value < 128 {
		return byte(value)
	}
	for code := 128; code <= math.MaxUint8; code++ {
		if decodeFloating8(byte(code)) >= value {
			return byte(code)
		}
	}
	return math.MaxUint8
}

func decodeFloating8(code byte) uint32 {
	if code < 128 {
		return uint32(code)
	}
	exponent := uint32(code>>4&7) + 3
	mantissa := uint32(code&15) | 16
	return mantissa << exponent
}

func encodeFloating16(value uint64) uint16 {
	if value < 0x8000 {
		return uint16(value)
	}
	for code := uint32(0x8000); code <= math.MaxUint16; code++ {
		if decodeFloating16(uint16(code)) >= value {
			return uint16(code)
		}
	}
	return math.MaxUint16
}

func decodeFloating16(code uint16) uint64 {
	if code < 0x8000 {
		return uint64(code)
	}
	exponent := uint(code>>12&7) + 3
	mantissa := uint64(code&0x0fff) | 0x1000
	return mantissa << exponent
}

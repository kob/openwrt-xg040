// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
)

var ErrNotMembership = errors.New("not an IGMP/MLD membership message")

type MessageKind uint8

const (
	MessageQuery MessageKind = iota + 1
	MessageReport
)

// RecordType uses the IGMPv3/MLDv2 record values. Legacy reports are
// normalized to exclude mode and legacy leave messages to an empty include
// mode, which lets the runtime use one state transition implementation.
type RecordType uint8

const (
	ModeIsInclude       RecordType = 1
	ModeIsExclude       RecordType = 2
	ChangeToIncludeMode RecordType = 3
	ChangeToExcludeMode RecordType = 4
	AllowNewSources     RecordType = 5
	BlockOldSources     RecordType = 6
)

type MembershipRecord struct {
	Type    RecordType
	Group   netip.Addr
	Sources []netip.Addr
}

type VLANTag struct {
	TPID uint16
	TCI  uint16
}

type MembershipMessage struct {
	Kind                 MessageKind
	Version              uint8
	Downstream           bool
	VLAN                 VLAN
	Client               netip.Addr
	SourceMAC            [6]byte
	DestinationMAC       [6]byte
	QueryRobustness      uint8
	QueryInterval        uint32
	QueryMaxResponseTime uint32
	Tags                 []VLANTag
	Records              []MembershipRecord
}

// ParseMembershipFrame validates one Ethernet IGMP or MLD frame. One or two
// VLAN headers are accepted; G.988 policy matching uses the outermost VID.
func ParseMembershipFrame(frame []byte) (MembershipMessage, error) {
	if len(frame) < 14 {
		return MembershipMessage{}, fmt.Errorf("membership Ethernet frame is truncated")
	}
	var result MembershipMessage
	copy(result.DestinationMAC[:], frame[0:6])
	copy(result.SourceMAC[:], frame[6:12])
	offset := 14
	etherType := binary.BigEndian.Uint16(frame[12:14])
	for tags := 0; etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100; tags++ {
		if tags == 2 {
			return MembershipMessage{}, fmt.Errorf("membership Ethernet frame has more than two VLAN tags")
		}
		if len(frame) < offset+4 {
			return MembershipMessage{}, fmt.Errorf("membership VLAN header is truncated")
		}
		tci := binary.BigEndian.Uint16(frame[offset : offset+2])
		result.Tags = append(result.Tags, VLANTag{TPID: etherType, TCI: tci})
		if tags == 0 {
			result.VLAN = VLAN{Tagged: true, ID: tci & 0x0fff}
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}

	var err error
	switch etherType {
	case 0x0800:
		err = parseIGMP(frame[offset:], &result)
	case 0x86dd:
		err = parseMLD(frame[offset:], &result)
	default:
		return MembershipMessage{}, ErrNotMembership
	}
	if err != nil {
		return MembershipMessage{}, err
	}
	return result, nil
}

func parseIGMP(packet []byte, result *MembershipMessage) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return fmt.Errorf("IGMP IPv4 header is invalid or truncated")
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || totalLength < headerLength+8 || totalLength > len(packet) {
		return fmt.Errorf("IGMP IPv4 length is invalid")
	}
	if packet[9] != 2 {
		return ErrNotMembership
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x3fff != 0 {
		return fmt.Errorf("fragmented IGMP is not supported")
	}
	result.Client = netip.AddrFrom4([4]byte(packet[12:16]))
	payload := packet[headerLength:totalLength]
	if internetChecksum(payload) != 0 {
		return fmt.Errorf("IGMP checksum is invalid")
	}

	switch payload[0] {
	case 0x11:
		result.Kind = MessageQuery
		group := netip.AddrFrom4([4]byte(payload[4:8]))
		if group != netip.IPv4Unspecified() && !group.IsMulticast() {
			return fmt.Errorf("IGMP query group %s is not multicast", group)
		}
		record := MembershipRecord{Group: group}
		switch len(payload) {
		case 8:
			if payload[1] == 0 {
				result.Version = 1
			} else {
				result.Version = 2
				result.QueryMaxResponseTime = uint32(payload[1])
			}
		default:
			if len(payload) < 12 {
				return fmt.Errorf("IGMP query has invalid length")
			}
			sourceCount := int(binary.BigEndian.Uint16(payload[10:12]))
			if len(payload) != 12+sourceCount*4 {
				return fmt.Errorf("IGMPv3 query source list is truncated or has trailing bytes")
			}
			result.Version = 3
			result.QueryRobustness = payload[8] & 7
			result.QueryInterval = decodeFloating8(payload[9])
			result.QueryMaxResponseTime = decodeFloating8(payload[1])
			record.Sources = make([]netip.Addr, 0, sourceCount)
			for index := 0; index < sourceCount; index++ {
				start := 12 + index*4
				record.Sources = append(record.Sources,
					netip.AddrFrom4([4]byte(payload[start:start+4])))
			}
		}
		result.Records = []MembershipRecord{record}
		return nil
	case 0x12, 0x16, 0x17:
		group := netip.AddrFrom4([4]byte(payload[4:8]))
		if !group.IsMulticast() {
			return fmt.Errorf("IGMP group %s is not multicast", group)
		}
		result.Kind = MessageReport
		if payload[0] == 0x12 {
			result.Version = 1
		} else {
			result.Version = 2
		}
		recordType := ModeIsExclude
		if payload[0] == 0x17 {
			recordType = ChangeToIncludeMode
		}
		result.Records = []MembershipRecord{{Type: recordType, Group: group}}
		return nil
	case 0x22:
		result.Kind = MessageReport
		result.Version = 3
		return parseIGMPv3Records(payload, result)
	default:
		return ErrNotMembership
	}
}

func parseIGMPv3Records(payload []byte, result *MembershipMessage) error {
	if len(payload) < 8 {
		return fmt.Errorf("IGMPv3 report is truncated")
	}
	count := int(binary.BigEndian.Uint16(payload[6:8]))
	offset := 8
	result.Records = make([]MembershipRecord, 0, count)
	for index := 0; index < count; index++ {
		if len(payload)-offset < 8 {
			return fmt.Errorf("IGMPv3 record %d is truncated", index)
		}
		typeValue := RecordType(payload[offset])
		if typeValue < ModeIsInclude || typeValue > BlockOldSources {
			return fmt.Errorf("IGMPv3 record %d has invalid type %d", index, typeValue)
		}
		auxLength := int(payload[offset+1]) * 4
		sourceCount := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		recordLength := 8 + sourceCount*4 + auxLength
		if len(payload)-offset < recordLength {
			return fmt.Errorf("IGMPv3 record %d sources are truncated", index)
		}
		group := netip.AddrFrom4([4]byte(payload[offset+4 : offset+8]))
		if !group.IsMulticast() {
			return fmt.Errorf("IGMPv3 record %d group %s is not multicast", index, group)
		}
		record := MembershipRecord{Type: typeValue, Group: group,
			Sources: make([]netip.Addr, 0, sourceCount)}
		for sourceIndex := 0; sourceIndex < sourceCount; sourceIndex++ {
			start := offset + 8 + sourceIndex*4
			record.Sources = append(record.Sources, netip.AddrFrom4([4]byte(payload[start:start+4])))
		}
		result.Records = append(result.Records, record)
		offset += recordLength
	}
	if offset != len(payload) {
		return fmt.Errorf("IGMPv3 report has trailing bytes")
	}
	return nil
}

func parseMLD(packet []byte, result *MembershipMessage) error {
	if len(packet) < 48 || packet[0]>>4 != 6 {
		return fmt.Errorf("MLD IPv6 header is invalid or truncated")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLength+40 > len(packet) {
		return fmt.Errorf("MLD IPv6 payload is truncated")
	}
	end := 40 + payloadLength
	nextHeader := packet[6]
	offset := 40
	for nextHeader == 0 || nextHeader == 43 || nextHeader == 60 {
		if end-offset < 8 {
			return fmt.Errorf("MLD IPv6 extension header is truncated")
		}
		length := (int(packet[offset+1]) + 1) * 8
		if length > end-offset {
			return fmt.Errorf("MLD IPv6 extension header length is invalid")
		}
		nextHeader = packet[offset]
		offset += length
	}
	if nextHeader == 44 {
		return fmt.Errorf("fragmented MLD is not supported")
	}
	if nextHeader != 58 {
		return ErrNotMembership
	}
	payload := packet[offset:end]
	if len(payload) < 8 {
		return fmt.Errorf("MLD ICMPv6 payload is truncated")
	}
	source := [16]byte(packet[8:24])
	destination := [16]byte(packet[24:40])
	if icmpv6Checksum(source, destination, payload) != 0 {
		return fmt.Errorf("MLD checksum is invalid")
	}
	result.Client = netip.AddrFrom16(source)

	switch payload[0] {
	case 130:
		if len(payload) < 24 {
			return fmt.Errorf("MLD query is truncated")
		}
		group := netip.AddrFrom16([16]byte(payload[8:24]))
		if group != netip.IPv6Unspecified() && !group.IsMulticast() {
			return fmt.Errorf("MLD query group %s is not multicast", group)
		}
		result.Kind = MessageQuery
		record := MembershipRecord{Group: group}
		if len(payload) == 24 {
			result.Version = 16
			milliseconds := uint32(binary.BigEndian.Uint16(payload[4:6]))
			result.QueryMaxResponseTime = (milliseconds + 99) / 100
		} else {
			if len(payload) < 28 {
				return fmt.Errorf("MLDv2 query is truncated")
			}
			sourceCount := int(binary.BigEndian.Uint16(payload[26:28]))
			if len(payload) != 28+sourceCount*16 {
				return fmt.Errorf("MLDv2 query source list is truncated or has trailing bytes")
			}
			result.Version = 17
			result.QueryRobustness = payload[24] & 7
			result.QueryInterval = decodeFloating8(payload[25])
			milliseconds := decodeFloating16(binary.BigEndian.Uint16(payload[4:6]))
			result.QueryMaxResponseTime = uint32(min((milliseconds+99)/100, uint64(math.MaxUint32)))
			record.Sources = make([]netip.Addr, 0, sourceCount)
			for index := 0; index < sourceCount; index++ {
				start := 28 + index*16
				record.Sources = append(record.Sources,
					netip.AddrFrom16([16]byte(payload[start:start+16])))
			}
		}
		result.Records = []MembershipRecord{record}
		return nil
	case 131, 132:
		if len(payload) != 24 {
			return fmt.Errorf("MLDv1 message has invalid length")
		}
		group := netip.AddrFrom16([16]byte(payload[8:24]))
		if !group.IsMulticast() {
			return fmt.Errorf("MLDv1 group %s is not multicast", group)
		}
		result.Kind = MessageReport
		result.Version = 16
		recordType := ModeIsExclude
		if payload[0] == 132 {
			recordType = ChangeToIncludeMode
		}
		result.Records = []MembershipRecord{{Type: recordType, Group: group}}
		return nil
	case 143:
		result.Kind = MessageReport
		result.Version = 17
		return parseMLDv2Records(payload, result)
	default:
		return ErrNotMembership
	}
}

func parseMLDv2Records(payload []byte, result *MembershipMessage) error {
	if len(payload) < 8 {
		return fmt.Errorf("MLDv2 report is truncated")
	}
	count := int(binary.BigEndian.Uint16(payload[6:8]))
	offset := 8
	result.Records = make([]MembershipRecord, 0, count)
	for index := 0; index < count; index++ {
		if len(payload)-offset < 20 {
			return fmt.Errorf("MLDv2 record %d is truncated", index)
		}
		typeValue := RecordType(payload[offset])
		if typeValue < ModeIsInclude || typeValue > BlockOldSources {
			return fmt.Errorf("MLDv2 record %d has invalid type %d", index, typeValue)
		}
		auxLength := int(payload[offset+1]) * 4
		sourceCount := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		recordLength := 20 + sourceCount*16 + auxLength
		if len(payload)-offset < recordLength {
			return fmt.Errorf("MLDv2 record %d sources are truncated", index)
		}
		group := netip.AddrFrom16([16]byte(payload[offset+4 : offset+20]))
		if !group.IsMulticast() {
			return fmt.Errorf("MLDv2 record %d group %s is not multicast", index, group)
		}
		record := MembershipRecord{Type: typeValue, Group: group,
			Sources: make([]netip.Addr, 0, sourceCount)}
		for sourceIndex := 0; sourceIndex < sourceCount; sourceIndex++ {
			start := offset + 20 + sourceIndex*16
			record.Sources = append(record.Sources, netip.AddrFrom16([16]byte(payload[start:start+16])))
		}
		result.Records = append(result.Records, record)
		offset += recordLength
	}
	if offset != len(payload) {
		return fmt.Errorf("MLDv2 report has trailing bytes")
	}
	return nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func icmpv6Checksum(source, destination [16]byte, payload []byte) uint16 {
	pseudo := make([]byte, 40+len(payload))
	copy(pseudo[0:16], source[:])
	copy(pseudo[16:32], destination[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(payload)))
	pseudo[39] = 58
	copy(pseudo[40:], payload)
	return internetChecksum(pseudo)
}

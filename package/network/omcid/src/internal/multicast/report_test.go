// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseIGMPv3TaggedReport(t *testing.T) {
	igmp := make([]byte, 8+8+8)
	igmp[0] = 0x22
	binary.BigEndian.PutUint16(igmp[6:8], 1)
	igmp[8] = byte(ModeIsInclude)
	binary.BigEndian.PutUint16(igmp[10:12], 2)
	copy(igmp[12:16], netip.MustParseAddr("239.1.2.3").AsSlice())
	copy(igmp[16:20], netip.MustParseAddr("192.0.2.1").AsSlice())
	copy(igmp[20:24], netip.MustParseAddr("192.0.2.2").AsSlice())
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))
	frame := ipv4MembershipFrame(t, igmp, true)

	message, err := ParseMembershipFrame(frame)
	if err != nil {
		t.Fatalf("ParseMembershipFrame() error = %v", err)
	}
	if message.Kind != MessageReport || message.Version != 3 ||
		message.VLAN != (VLAN{Tagged: true, ID: 100}) ||
		message.Client != netip.MustParseAddr("192.0.2.10") || len(message.Records) != 1 ||
		message.Records[0].Type != ModeIsInclude ||
		message.Records[0].Group != netip.MustParseAddr("239.1.2.3") ||
		len(message.Records[0].Sources) != 2 {
		t.Fatalf("message = %+v", message)
	}
}

func TestParseMLDv2Report(t *testing.T) {
	icmp := make([]byte, 8+20+16)
	icmp[0] = 143
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	icmp[8] = byte(ChangeToIncludeMode)
	binary.BigEndian.PutUint16(icmp[10:12], 1)
	copy(icmp[12:28], netip.MustParseAddr("ff3e::1234").AsSlice())
	copy(icmp[28:44], netip.MustParseAddr("2001:db8::1").AsSlice())
	source := netip.MustParseAddr("fe80::10").As16()
	destination := netip.MustParseAddr("ff02::16").As16()
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(source, destination, icmp))

	frame := make([]byte, 14+40+len(icmp))
	copy(frame[0:6], []byte{0x33, 0x33, 0, 0, 0, 0x16})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmp)))
	ip[6], ip[7] = 58, 1
	copy(ip[8:24], source[:])
	copy(ip[24:40], destination[:])
	copy(ip[40:], icmp)

	message, err := ParseMembershipFrame(frame)
	if err != nil {
		t.Fatalf("ParseMembershipFrame() error = %v", err)
	}
	if message.Version != 17 || len(message.Records) != 1 ||
		message.Records[0].Group != netip.MustParseAddr("ff3e::1234") ||
		len(message.Records[0].Sources) != 1 ||
		message.Records[0].Sources[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("message = %+v", message)
	}
}

func TestParseMembershipRejectsChecksumAndTrailingRecords(t *testing.T) {
	igmp := []byte{0x16, 0, 0, 0, 239, 1, 2, 3}
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))
	frame := ipv4MembershipFrame(t, igmp, false)
	frame[len(frame)-1] ^= 1
	if _, err := ParseMembershipFrame(frame); err == nil {
		t.Fatal("invalid IGMP checksum was accepted")
	}

	igmp = make([]byte, 17)
	igmp[0] = 0x22
	binary.BigEndian.PutUint16(igmp[6:8], 1)
	igmp[8] = byte(ModeIsExclude)
	copy(igmp[12:16], netip.MustParseAddr("239.1.2.3").AsSlice())
	binary.BigEndian.PutUint16(igmp[2:4], internetChecksum(igmp))
	if _, err := ParseMembershipFrame(ipv4MembershipFrame(t, igmp, false)); err == nil {
		t.Fatal("IGMPv3 report with trailing bytes was accepted")
	}
}

func ipv4MembershipFrame(t *testing.T, payload []byte, tagged bool) []byte {
	t.Helper()
	offset := 14
	if tagged {
		offset += 4
	}
	frame := make([]byte, offset+20+len(payload))
	copy(frame[0:6], []byte{0x01, 0, 0x5e, 1, 2, 3})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	if tagged {
		binary.BigEndian.PutUint16(frame[12:14], 0x8100)
		binary.BigEndian.PutUint16(frame[14:16], 100)
		binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	} else {
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	}
	ip := frame[offset:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(payload)))
	ip[8], ip[9] = 1, 2
	copy(ip[12:16], netip.MustParseAddr("192.0.2.10").AsSlice())
	copy(ip[16:20], netip.MustParseAddr("224.0.0.22").AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip[:20]))
	copy(ip[20:], payload)
	return frame
}

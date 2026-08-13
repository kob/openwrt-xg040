// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildUpstreamIGMPv3TagControls(t *testing.T) {
	base := UpstreamReport{
		Join: true, Profile: Profile{EntityID: 1, IGMPVersion: 3, UpstreamTCI: 0xa123},
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), Group: addr("239.1.2.3"),
			Client: addr("192.0.2.10")},
		SourceMAC: [6]byte{2, 0, 0, 0, 0, 1},
		Tags:      []VLANTag{{TPID: 0x88a8, TCI: 0x6123}},
	}
	for _, test := range []struct {
		control uint8
		tags    []VLANTag
	}{
		{control: 0, tags: []VLANTag{{TPID: 0x88a8, TCI: 0x6123}}},
		{control: 1, tags: []VLANTag{{TPID: 0x8100, TCI: 0xa123}, {TPID: 0x88a8, TCI: 0x6123}}},
		{control: 2, tags: []VLANTag{{TPID: 0x88a8, TCI: 0xa123}}},
		{control: 3, tags: []VLANTag{{TPID: 0x88a8, TCI: 0x6123}}},
	} {
		report := base
		report.Profile.UpstreamTagControl = test.control
		frame, err := BuildUpstreamFrame(report)
		if err != nil {
			t.Fatalf("BuildUpstreamFrame(control=%d) error = %v", test.control, err)
		}
		message, err := ParseMembershipFrame(frame)
		if err != nil {
			t.Fatalf("ParseMembershipFrame(control=%d) error = %v", test.control, err)
		}
		if len(message.Tags) != len(test.tags) {
			t.Fatalf("control %d tags = %+v, want %+v", test.control, message.Tags, test.tags)
		}
		for index := range test.tags {
			if message.Tags[index] != test.tags[index] {
				t.Fatalf("control %d tags = %+v, want %+v", test.control, message.Tags, test.tags)
			}
		}
		if message.Version != 3 || len(message.Records) != 1 ||
			message.Records[0].Type != ChangeToExcludeMode || message.Records[0].Group != base.Group.Group {
			t.Fatalf("control %d parsed message = %+v", test.control, message)
		}
	}
}

func TestBuildUpstreamMLDv2SourceSpecificLeave(t *testing.T) {
	report := UpstreamReport{
		Profile: Profile{EntityID: 1, IGMPVersion: 17},
		Group: ActiveGroup{Source: addr("2001:db8::1"), Group: addr("ff3e::1234"),
			Client: addr("fe80::10")},
		SourceMAC: [6]byte{2, 0, 0, 0, 0, 1},
	}
	frame, err := BuildUpstreamFrame(report)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame() error = %v", err)
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil {
		t.Fatalf("ParseMembershipFrame() error = %v", err)
	}
	if message.Version != 17 || len(message.Records) != 1 ||
		message.Records[0].Type != BlockOldSources ||
		len(message.Records[0].Sources) != 1 || message.Records[0].Sources[0] != report.Group.Source {
		t.Fatalf("parsed MLD leave = %+v", message)
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x86dd {
		t.Fatalf("EtherType = %#x", binary.BigEndian.Uint16(frame[12:14]))
	}
}

func TestBuildIGMPv3ExcludeReportCarriesExcludedSources(t *testing.T) {
	report := UpstreamReport{Join: true, Profile: Profile{IGMPVersion: 3}, Group: ActiveGroup{
		Source: netip.IPv4Unspecified(), Group: addr("239.1.2.3"), Client: addr("192.0.2.10"),
		ExcludedSources: []netip.Addr{addr("192.0.2.8"), addr("192.0.2.9")},
	}, SourceMAC: [6]byte{2, 0, 0, 0, 0, 1}}
	frame, err := BuildUpstreamFrame(report)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame() error = %v", err)
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil {
		t.Fatalf("ParseMembershipFrame() error = %v", err)
	}
	if len(message.Records) != 1 || message.Records[0].Type != ChangeToExcludeMode ||
		len(message.Records[0].Sources) != 2 || message.Records[0].Sources[0] != addr("192.0.2.8") ||
		message.Records[0].Sources[1] != addr("192.0.2.9") {
		t.Fatalf("parsed EXCLUDE record = %+v", message.Records)
	}
}

func TestBuildMLDv2ExcludeReportCarriesExcludedSources(t *testing.T) {
	report := UpstreamReport{Join: true, Profile: Profile{IGMPVersion: 17}, Group: ActiveGroup{
		Source: netip.IPv6Unspecified(), Group: addr("ff3e::1234"), Client: addr("2001:db8::10"),
		ExcludedSources: []netip.Addr{addr("2001:db8::8"), addr("2001:db8::9")},
	}, SourceMAC: [6]byte{2, 0, 0, 0, 0, 1}}
	frame, err := BuildUpstreamFrame(report)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame() error = %v", err)
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil {
		t.Fatalf("ParseMembershipFrame() error = %v", err)
	}
	if len(message.Records) != 1 || message.Records[0].Type != ChangeToExcludeMode ||
		len(message.Records[0].Sources) != 2 || message.Records[0].Sources[0] != addr("2001:db8::8") ||
		message.Records[0].Sources[1] != addr("2001:db8::9") {
		t.Fatalf("parsed EXCLUDE record = %+v", message.Records)
	}
}

func TestBuildIGMPv3IncludeReportCarriesAggregateSources(t *testing.T) {
	report := UpstreamReport{Join: true, Profile: Profile{IGMPVersion: 3}, Group: ActiveGroup{
		Source: addr("192.0.2.8"), Group: addr("239.1.2.3"), Client: addr("192.0.2.10"),
		IncludedSources: []netip.Addr{addr("192.0.2.8"), addr("192.0.2.9")},
	}, SourceMAC: [6]byte{2, 0, 0, 0, 0, 1}}
	frame, err := BuildUpstreamFrame(report)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame() error = %v", err)
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil {
		t.Fatalf("ParseMembershipFrame() error = %v", err)
	}
	if len(message.Records) != 1 || message.Records[0].Type != ChangeToIncludeMode ||
		len(message.Records[0].Sources) != 2 || message.Records[0].Sources[0] != addr("192.0.2.8") ||
		message.Records[0].Sources[1] != addr("192.0.2.9") {
		t.Fatalf("parsed INCLUDE record = %+v", message.Records)
	}
}

func TestBuildUpstreamIGMPv1LeaveIsEmpty(t *testing.T) {
	report := UpstreamReport{
		Profile: Profile{EntityID: 1, IGMPVersion: 1},
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), Group: addr("239.1.2.3"),
			Client: addr("192.0.2.10")},
	}
	frame, err := BuildUpstreamFrame(report)
	if err != nil || frame != nil {
		t.Fatalf("BuildUpstreamFrame(IGMPv1 leave) = %x, %v", frame, err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildIGMPv3GeneralAndSourceSpecificQueries(t *testing.T) {
	profile := Profile{EntityID: 1, IGMPVersion: 3, Robustness: 3,
		QuerierIPAddress: 0xc0000201, QueryInterval: 200, QueryMaxResponseTime: 300}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	frame, err := BuildDownstreamQueryFrame(DownstreamQuery{Profile: profile,
		Tags: []VLANTag{{TPID: 0x8100, TCI: 100}}}, mac)
	if err != nil {
		t.Fatalf("BuildDownstreamQueryFrame(general) error = %v", err)
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil || message.Kind != MessageQuery || message.VLAN.ID != 100 ||
		message.Records[0].Group != netip.IPv4Unspecified() || message.Version != 3 ||
		message.QueryRobustness != 3 || message.QueryInterval < 200 ||
		message.QueryMaxResponseTime < 300 {
		t.Fatalf("general query parse = %+v, %v", message, err)
	}
	if got := netip.AddrFrom4([4]byte(frame[30:34])); got != addr("192.0.2.1") {
		t.Fatalf("querier source = %s", got)
	}
	if frame[50]&7 != 3 || decodeFloating8(frame[51]) < 200 || decodeFloating8(frame[43]) < 300 {
		t.Fatalf("IGMPv3 query parameters = %x", frame[42:52])
	}

	query := DownstreamQuery{Profile: profile, Group: addr("239.1.0.1"), Source: addr("192.0.2.55")}
	frame, err = BuildDownstreamQueryFrame(query, mac)
	if err != nil {
		t.Fatalf("BuildDownstreamQueryFrame(source-specific) error = %v", err)
	}
	if binary.BigEndian.Uint16(frame[48:50]) != 1 || netip.AddrFrom4([4]byte(frame[50:54])) != query.Source {
		t.Fatalf("source-specific query payload = %x", frame[38:])
	}
}

func TestBuildMLDv2GroupQuery(t *testing.T) {
	profile := Profile{EntityID: 2, IGMPVersion: 17, Robustness: 2,
		QueryInterval: 125, QueryMaxResponseTime: 100}
	query := DownstreamQuery{Profile: profile, Group: addr("ff3e::1234"), Source: addr("2001:db8::1")}
	frame, err := BuildDownstreamQueryFrame(query, [6]byte{2, 0, 0, 0, 0, 2})
	if err != nil {
		t.Fatalf("BuildDownstreamQueryFrame() error = %v", err)
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil || message.Kind != MessageQuery || message.Records[0].Group != query.Group {
		t.Fatalf("MLDv2 query parse = %+v, %v", message, err)
	}
	if binary.BigEndian.Uint16(frame[88:90]) != 1 || netip.AddrFrom16([16]byte(frame[90:106])) != query.Source {
		t.Fatalf("MLDv2 source-specific query = %x", frame[62:])
	}
}

func TestBuildLegacyQueryRejectsSource(t *testing.T) {
	_, err := BuildDownstreamQueryFrame(DownstreamQuery{
		Profile: Profile{EntityID: 1, IGMPVersion: 2}, Group: addr("239.1.0.1"), Source: addr("192.0.2.1"),
	}, [6]byte{})
	if err == nil {
		t.Fatal("legacy source-specific query unexpectedly succeeded")
	}
}

func TestBuildIGMPv2GroupQueryUsesLinearLastMemberResponse(t *testing.T) {
	profile := Profile{EntityID: 1, IGMPVersion: 2,
		QueryMaxResponseTime: 1000, LastMemberQueryInterval: 25}
	frame, err := BuildDownstreamQueryFrame(DownstreamQuery{
		Profile: profile, Group: addr("239.1.0.1"),
	}, [6]byte{2, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("BuildDownstreamQueryFrame() error = %v", err)
	}
	// Ethernet (14) + IPv4 with Router Alert (24) + IGMP max-response byte.
	if frame[39] != 25 {
		t.Fatalf("IGMPv2 last-member response code = %d, want 25", frame[39])
	}
	message, err := ParseMembershipFrame(frame)
	if err != nil || message.Version != 2 || message.QueryMaxResponseTime != 25 {
		t.Fatalf("parsed IGMPv2 query = %+v, %v", message, err)
	}
}

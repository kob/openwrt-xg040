// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSendEthernetFrameMarkedIntegration(t *testing.T) {
	interfaceName := os.Getenv("AIROHA_MCAST_TEST_INTERFACE")
	if interfaceName == "" {
		t.Skip("set AIROHA_MCAST_TEST_INTERFACE inside an isolated network namespace")
	}
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0x01, 0x00, 0x5e, 0, 0, 1})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	frame[12], frame[13] = 0x08, 0x00
	if err := sendEthernetFrameMarked(interfaceName, frame, proxyQueryMark); err != nil {
		t.Fatalf("sendEthernetFrameMarked() error = %v", err)
	}
}

type recordedCommand struct {
	name      string
	arguments []string
}

type recordingCommandRunner struct {
	commands  []recordedCommand
	output    []byte
	outputErr error
}

func (r *recordingCommandRunner) Run(name string, arguments ...string) error {
	r.commands = append(r.commands, recordedCommand{name: name,
		arguments: append([]string(nil), arguments...)})
	return nil
}

func (r *recordingCommandRunner) Output(name string, arguments ...string) ([]byte, error) {
	r.commands = append(r.commands, recordedCommand{name: name,
		arguments: append([]string(nil), arguments...)})
	return append([]byte(nil), r.output...), r.outputErr
}

func TestAddressRangePrefixes(t *testing.T) {
	prefixes, err := addressRangePrefixes(addr("239.1.0.1"), addr("239.1.0.6"))
	if err != nil {
		t.Fatalf("addressRangePrefixes(IPv4) error = %v", err)
	}
	if got, want := prefixStrings(prefixes), []string{
		"239.1.0.1/32", "239.1.0.2/31", "239.1.0.4/31", "239.1.0.6/32",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 prefixes = %v, want %v", got, want)
	}
	prefixes, err = addressRangePrefixes(addr("ff3e::1"), addr("ff3e::6"))
	if err != nil {
		t.Fatalf("addressRangePrefixes(IPv6) error = %v", err)
	}
	if got, want := prefixStrings(prefixes), []string{
		"ff3e::1/128", "ff3e::2/127", "ff3e::4/127", "ff3e::6/128",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 prefixes = %v, want %v", got, want)
	}
}

func TestLinuxBackendBuildsStaticRangeAndDefaultDrop(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner})
	entry := acl(1, "239.1.0.1", "239.1.0.2", 100)
	configured := profile(1)
	configured.StaticACL = []ACLEntry{entry}
	if err := backend.Configure(Config{
		Profiles: []Profile{configured},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1,
			Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}}}},
	}); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	joined := commandLines(runner.commands)
	for _, expected := range []string{
		"tc-test filter del dev lan1 egress chain 2013",
		"handle 0xa17f0001 fw action pass",
		"ip_proto 2 action goto chain 2012",
		"dst_ip 239.1.0.1/32 action goto chain 2012",
		"dst_ip 239.1.0.2/32 action goto chain 2012",
		"protocol all pref 65000 flower skip_hw action drop",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("commands do not contain %q:\n%s", expected, joined)
		}
	}
}

func TestLinuxBackendDispatchesEachGEMToAnIsolatedChain(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner})
	first := acl(1, "239.1.0.1", "239.1.0.1", 100)
	first.GEMPortID = 201
	second := acl(2, "239.1.0.1", "239.1.0.1", 100)
	second.GEMPortID = 202
	configured := profile(1, first, second)
	if err := backend.Configure(Config{Profiles: []Profile{configured}, Subscribers: []Subscriber{{
		EntityID: 10, Profile: 1, Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}},
	}}}); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	joined := commandLines(runner.commands)
	for _, expected := range []string{
		"handle 0xa17000c9/0xffffffff fw action goto chain 20201",
		"handle 0xa17000ca/0xffffffff fw action goto chain 20202",
		"dev lan1 egress chain 20201",
		"dev lan1 egress chain 20202",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("GEM-isolated rules do not contain %q:\n%s", expected, joined)
		}
	}
}

func TestLinuxBackendInstallsExcludeSourceDropBeforeDynamicPass(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner})
	configured := profile(1, acl(1, "239.1.0.1", "239.1.0.1", 100))
	config := Config{Profiles: []Profile{configured}, Subscribers: []Subscriber{{
		EntityID: 10, Profile: 1, Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}},
	}}}
	if err := backend.Configure(config); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	runner.commands = nil
	if err := backend.SetReplication(ReplicationChange{Enable: true, Subscriber: config.Subscribers[0],
		Attachment: config.Subscribers[0].Attachments[0], Profile: configured,
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), ExcludedSources: []netip.Addr{addr("192.0.2.9")},
			Group: addr("239.1.0.1"), ANIVLAN: 100, GEMPortID: 200}}); err != nil {
		t.Fatalf("SetReplication() error = %v", err)
	}
	joined := commandLines(runner.commands)
	drop := "src_ip 192.0.2.9 dst_ip 239.1.0.1/32 action drop"
	pass := "dst_ip 239.1.0.1/32 action goto chain 2012"
	dropIndex, passIndex := strings.Index(joined, drop), strings.Index(joined, pass)
	if dropIndex < 0 || passIndex < 0 || dropIndex > passIndex {
		t.Fatalf("exclude source was not dropped before pass:\n%s", joined)
	}
}

func TestLinuxBackendIncludeSourceOverridesExcludeDropOnSameGEM(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner})
	configured := profile(1, acl(1, "239.1.0.1", "239.1.0.1", 100))
	config := Config{Profiles: []Profile{configured}, Subscribers: []Subscriber{{
		EntityID: 10, Profile: 1, Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}},
	}}}
	if err := backend.Configure(config); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	wildcard := ReplicationChange{Enable: true, Subscriber: config.Subscribers[0],
		Attachment: config.Subscribers[0].Attachments[0], Profile: configured,
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), ExcludedSources: []netip.Addr{addr("192.0.2.9")},
			Group: addr("239.1.0.1"), ANIVLAN: 100, GEMPortID: 200}}
	if err := backend.SetReplication(wildcard); err != nil {
		t.Fatalf("SetReplication(EXCLUDE) error = %v", err)
	}
	runner.commands = nil
	include := wildcard
	include.Group.Source = addr("192.0.2.9")
	include.Group.ExcludedSources = nil
	if err := backend.SetReplication(include); err != nil {
		t.Fatalf("SetReplication(INCLUDE) error = %v", err)
	}
	joined := commandLines(runner.commands)
	if strings.Contains(joined, "src_ip 192.0.2.9 dst_ip 239.1.0.1/32 action drop") {
		t.Fatalf("INCLUDE source is still excluded:\n%s", joined)
	}
	specific := strings.Index(joined, "src_ip 192.0.2.9 dst_ip 239.1.0.1/32")
	wildcardPass := strings.Index(joined, "flower skip_hw num_of_vlans 1 vlan_id 100 vlan_ethtype ip dst_ip 239.1.0.1/32")
	if specific < 0 || wildcardPass < 0 || specific > wildcardPass {
		t.Fatalf("source-specific pass does not precede wildcard pass:\n%s", joined)
	}
}

func TestLinuxBackendAppliesDownstreamControlToOLTQueries(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner})
	configured := profile(1, acl(1, "239.1.0.1", "239.1.0.1", 100))
	configured.DynamicACL = append(configured.DynamicACL, acl(2, "239.1.0.2", "239.1.0.2", 0))
	configured.DownstreamTagControl = 3
	configured.DownstreamTCI = 0xa123
	if err := backend.Configure(Config{
		Profiles: []Profile{configured},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1,
			Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}}}},
	}); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	joined := commandLines(runner.commands)
	for _, expected := range []string{
		"vlan_id 100 vlan_ethtype ip ip_proto 2 action vlan modify id 291 priority 5 dei 0",
		"protocol ip pref 10 flower skip_hw ip_proto 2 action vlan push protocol 802.1Q id 291 priority 5 dei 0",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("query filters do not contain %q:\n%s", expected, joined)
		}
	}
}

func TestLinuxBackendDynamicDownstreamTagReplacement(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner})
	configured := profile(1, acl(1, "239.1.0.1", "239.1.0.1", 100))
	configured.DownstreamTagControl = 3
	configured.DownstreamTCI = 0xa123
	config := Config{
		Profiles: []Profile{configured},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1,
			Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}}}},
	}
	if err := backend.Configure(config); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	runner.commands = nil
	if err := backend.SetReplication(ReplicationChange{Enable: true,
		Subscriber: config.Subscribers[0], Attachment: config.Subscribers[0].Attachments[0],
		Profile: configured, Group: ActiveGroup{Source: netip.IPv4Unspecified(),
			Group: addr("239.1.0.1"), ANIVLAN: 100}},
	); err != nil {
		t.Fatalf("SetReplication() error = %v", err)
	}
	joined := commandLines(runner.commands)
	if !strings.Contains(joined, "vlan_id 100") ||
		!strings.Contains(joined, "action vlan modify id 291 priority 5 dei 0") {
		t.Fatalf("dynamic filter does not replace downstream TCI:\n%s", joined)
	}
}

func TestLinuxBackendSamplesDynamicFilterByteRateAndResetsBaseline(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{TC: "tc-test", Runner: runner,
		Now: func() time.Time { return now }})
	configured := profile(1, acl(1, "239.1.0.1", "239.1.0.1", 100))
	config := Config{Profiles: []Profile{configured}, Subscribers: []Subscriber{{
		EntityID: 10, Profile: 1, Attachments: []Attachment{{Interface: "lan1", BridgeEntity: 0x100}},
	}}}
	if err := backend.Configure(config); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	change := ReplicationChange{Enable: true, Subscriber: config.Subscribers[0],
		Attachment: config.Subscribers[0].Attachments[0], Profile: configured,
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), Group: addr("239.1.0.1"), ANIVLAN: 100}}
	if err := backend.SetReplication(change); err != nil {
		t.Fatalf("SetReplication() error = %v", err)
	}
	key := dynamicRuleKey{subscriberID: 10, interfaceName: "lan1",
		source: netip.IPv4Unspecified(), group: addr("239.1.0.1")}
	references := backend.filters[key]
	if len(references) != 4 {
		t.Fatalf("dynamic filter references = %+v, want four tagged variants", references)
	}
	setCounters := func(value uint64) {
		t.Helper()
		filters := make([]map[string]interface{}, 0, len(references))
		for _, reference := range references {
			filters = append(filters, map[string]interface{}{
				"pref": reference.preference, "protocol": "802.1Q", "kind": "flower",
			})
			filters = append(filters, map[string]interface{}{
				"pref": reference.preference,
				"options": map[string]interface{}{"actions": []interface{}{
					map[string]interface{}{"stats": map[string]interface{}{"bytes": value}},
					map[string]interface{}{"stats": map[string]interface{}{"bytes": value}},
				}},
			})
		}
		runner.output, _ = json.Marshal(filters)
	}
	setCounters(100)
	if samples, err := backend.SampleBandwidth(); err != nil || len(samples) != 0 {
		t.Fatalf("first SampleBandwidth() = %+v, %v, want baseline only", samples, err)
	}
	now = now.Add(2 * time.Second)
	setCounters(600)
	samples, err := backend.SampleBandwidth()
	wantKey := BandwidthKey{SubscriberID: 10, Interface: "lan1",
		Source: netip.IPv4Unspecified(), Group: addr("239.1.0.1")}
	if err != nil || samples[wantKey] != 1000 {
		t.Fatalf("SampleBandwidth() = %+v, %v, want 1000 bytes/s", samples, err)
	}

	now = now.Add(time.Second)
	setCounters(10)
	if samples, err := backend.SampleBandwidth(); err != nil || len(samples) != 0 {
		t.Fatalf("counter reset SampleBandwidth() = %+v, %v, want a new baseline", samples, err)
	}
	now = now.Add(time.Second)
	setCounters(110)
	if samples, err := backend.SampleBandwidth(); err != nil || samples[wantKey] != 400 {
		t.Fatalf("post-reset SampleBandwidth() = %+v, %v, want 400 bytes/s", samples, err)
	}

	if err := backend.SetReplication(change); err != nil {
		t.Fatalf("SetReplication(rebuild) error = %v", err)
	}
	setCounters(1000)
	if samples, err := backend.SampleBandwidth(); err != nil || len(samples) != 0 {
		t.Fatalf("post-rebuild SampleBandwidth() = %+v, %v, want baseline only", samples, err)
	}
}

func TestLinuxBackendBandwidthSamplingRejectsMissingOrInvalidCounters(t *testing.T) {
	runner := &recordingCommandRunner{}
	backend := NewLinuxBackend(LinuxBackendOptions{Runner: runner})
	backend.filters[dynamicRuleKey{subscriberID: 1, interfaceName: "lan1"}] =
		[]tcFilterRef{{interfaceName: "lan1", preference: 1000}}
	for name, output := range map[string]string{
		"invalid JSON":       `{`,
		"missing preference": `[{"pref":1001,"options":{"actions":[{"stats":{"bytes":1}}]}}]`,
		"missing stats":      `[{"pref":1000,"options":{"actions":[]}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			runner.output = []byte(output)
			if _, err := backend.SampleBandwidth(); err == nil {
				t.Fatal("SampleBandwidth() unexpectedly accepted invalid tc counters")
			}
		})
	}
	runner.outputErr = errors.New("tc failed")
	if _, err := backend.SampleBandwidth(); err == nil || !strings.Contains(err.Error(), "tc failed") {
		t.Fatalf("SampleBandwidth(output error) = %v", err)
	}
}

func TestLinuxBackendSendsDirectMapperReportOnMarkedPONPath(t *testing.T) {
	mapper := &UpstreamMapper{UnmarkedFrameOption: 1, DefaultPBit: 5}
	for priority := range mapper.GEMPortIDs {
		mapper.GEMPortIDs[priority] = ^uint16(0)
	}
	mapper.GEMPortIDs[5] = 205
	var device string
	var mark uint32
	var sent []byte
	backend := NewLinuxBackend(LinuxBackendOptions{
		Runner: &recordingCommandRunner{}, PON: "pon-test",
		MarkedSender: func(interfaceName string, frame []byte, packetMark uint32) error {
			device, mark, sent = interfaceName, packetMark, append([]byte(nil), frame...)
			return nil
		},
		Sender: func(string, []byte) error {
			t.Fatal("direct mapper report used bridge sender")
			return nil
		},
	})
	report := UpstreamReport{
		Join: true, Attachment: Attachment{Interface: "lan1", DirectMapper: mapper},
		Profile: Profile{EntityID: 1, IGMPVersion: 3, UpstreamTagControl: 1, UpstreamTCI: 5 << 13},
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), Group: addr("239.1.2.3"),
			Client: addr("192.0.2.10")},
		SourceMAC: [6]byte{2, 0, 0, 0, 0, 1},
	}
	if err := backend.SendReport(report); err != nil {
		t.Fatalf("SendReport() error = %v", err)
	}
	if device != "pon-test" || mark != gponGEMMarkKey|205 || len(sent) == 0 {
		t.Fatalf("direct report = device %q mark %#x frame %x", device, mark, sent)
	}
}

func TestDirectMapperGEMSelection(t *testing.T) {
	mapper := &UpstreamMapper{UnmarkedFrameOption: 1, DefaultPBit: 3}
	for priority := range mapper.GEMPortIDs {
		mapper.GEMPortIDs[priority] = uint16(200 + priority)
		mapper.DSCPToPBit[priority] = uint8(priority)
	}
	base := UpstreamReport{Join: true, Profile: Profile{EntityID: 1, IGMPVersion: 2},
		Group: ActiveGroup{Source: netip.IPv4Unspecified(), Group: addr("239.1.2.3"),
			Client: addr("192.0.2.10")}, SourceMAC: [6]byte{2, 0, 0, 0, 0, 1}}
	frame, err := BuildUpstreamFrame(base)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame(untagged) error = %v", err)
	}
	if gem, err := directMapperGEM(mapper, frame); err != nil || gem != 203 {
		t.Fatalf("directMapperGEM(default P-bit) = %d, %v, want 203", gem, err)
	}

	tagged := base
	tagged.Profile.UpstreamTagControl = 1
	tagged.Profile.UpstreamTCI = 6 << 13
	frame, err = BuildUpstreamFrame(tagged)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame(tagged) error = %v", err)
	}
	if gem, err := directMapperGEM(mapper, frame); err != nil || gem != 206 {
		t.Fatalf("directMapperGEM(tagged P-bit) = %d, %v, want 206", gem, err)
	}

	mapper.UnmarkedFrameOption = 0
	mapper.DSCPToPBit[0] = 2
	if gem, err := directMapperGEM(mapper, mustUpstreamFrame(t, base)); err != nil || gem != 202 {
		t.Fatalf("directMapperGEM(DSCP) = %d, %v, want 202", gem, err)
	}
	mapper.GEMPortIDs[2] = ^uint16(0)
	if _, err := directMapperGEM(mapper, mustUpstreamFrame(t, base)); err == nil ||
		!strings.Contains(err.Error(), "no upstream GEM") {
		t.Fatalf("directMapperGEM(null branch) error = %v", err)
	}
}

func mustUpstreamFrame(t *testing.T, report UpstreamReport) []byte {
	t.Helper()
	frame, err := BuildUpstreamFrame(report)
	if err != nil {
		t.Fatalf("BuildUpstreamFrame() error = %v", err)
	}
	return frame
}

func TestDownstreamActionsRepresentCompleteTCI(t *testing.T) {
	configured := profile(1)
	configured.DownstreamTCI = 5<<13 | 1<<12 | 291
	for _, test := range []struct {
		control uint8
		tagged  bool
		uniVLAN VLAN
		want    string
		reject  string
	}{
		{control: 2, want: "vlan push protocol 802.1Q id 291 priority 5 dei 1"},
		{control: 3, tagged: true, want: "vlan modify id 291 priority 5 dei 1"},
		{control: 4, tagged: true, want: "vlan modify id 291 pipe", reject: "priority"},
		{control: 4, want: "vlan push protocol 802.1Q id 291 pipe", reject: "priority"},
		{control: 5, want: "vlan push protocol 802.1Q id 291 priority 5 dei 1"},
		{control: 6, tagged: true, uniVLAN: VLAN{Tagged: true, ID: 291},
			want: "vlan modify id 291 priority 5 dei 1"},
		{control: 7, tagged: true, uniVLAN: VLAN{Tagged: true, ID: 291},
			want: "vlan modify id 291 pipe", reject: "dei"},
	} {
		configured.DownstreamTagControl = test.control
		actions, err := downstreamActions(configured, test.uniVLAN, test.tagged)
		joined := strings.Join(actions, " ")
		if err != nil || !strings.Contains(joined, test.want) {
			t.Errorf("control %d tagged %v = %q, %v, want %q", test.control,
				test.tagged, joined, err, test.want)
		}
		if test.reject != "" && strings.Contains(joined, test.reject) {
			t.Errorf("control %d tagged %v = %q, unexpectedly contains %q",
				test.control, test.tagged, joined, test.reject)
		}
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index := range prefixes {
		result[index] = prefixes[index].String()
	}
	return result
}

func commandLines(commands []recordedCommand) string {
	lines := make([]string, len(commands))
	for index, command := range commands {
		lines[index] = command.name + " " + strings.Join(command.arguments, " ")
	}
	return strings.Join(lines, "\n")
}

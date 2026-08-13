// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/multicast"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

const (
	testUNI       = 0x0101
	testTCONT     = 0x8001
	testBridge    = 0x0100
	testMapper    = 0x0200
	testGAL       = 0x0001
	testMapperIW  = 0x0300
	testBridgeIW  = 0x0301
	testMapperGEM = 0x0400
	testBridgeGEM = 0x0401
	uniBridgePort = 0x0500
	mapperPort    = 0x0501
	gemBridgePort = 0x0502
)

func TestBuildServiceGraphResolvesCompleteEthernetService(t *testing.T) {
	snapshot := validServiceSnapshot()
	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.UNIs) != 1 || graph.UNIs[0].EntityID != testUNI ||
		len(graph.TCONTs) != 1 || graph.TCONTs[0].AllocID != 100 ||
		len(graph.GEMPorts) != 2 || len(graph.Interworking) != 2 ||
		len(graph.Mappers) != 1 || len(graph.Bridges) != 1 ||
		len(graph.Bridges[0].Ports) != 3 || len(graph.VLANFilters) != 1 ||
		len(graph.ExtendedVLANs) != 1 {
		t.Fatalf("resolved graph = %#v", graph)
	}
	if graph.UNIs[0].Interface != "lan1" {
		t.Fatalf("Ethernet UNI interface = %q, want lan1", graph.UNIs[0].Interface)
	}
	for priority, pointer := range graph.Mappers[0].PBits {
		if pointer != testMapperIW {
			t.Fatalf("P-bit %d pointer = %#x, want %#x", priority, pointer, testMapperIW)
		}
	}
	if graph.Mappers[0].UnmarkedFrameOption != 1 || graph.Mappers[0].DefaultPBit != 0 {
		t.Fatalf("mapper unmarked policy = %d/%d, want fixed P-bit 0",
			graph.Mappers[0].UnmarkedFrameOption, graph.Mappers[0].DefaultPBit)
	}
	if graph.GEMPorts[0].AllocID != 100 || graph.GEMPorts[1].AllocID != 100 {
		t.Fatalf("GEM Alloc-IDs = %d/%d, want 100", graph.GEMPorts[0].AllocID, graph.GEMPorts[1].AllocID)
	}
	if graph.TCONTs[0].SchedulerPolicy != 0 || graph.TCONTs[0].QueueWeights[0] != 1 ||
		graph.TCONTs[0].QueueEntities[0] != 0x8000 {
		t.Fatalf("T-CONT QoS = %#v", graph.TCONTs[0])
	}
	bridge := graph.Bridges[0]
	if bridge.SpanningTree != 1 || bridge.Learning != 1 || bridge.PortBridging != 1 ||
		bridge.Priority != 0x9000 || bridge.MaxAge != 20*256 || bridge.HelloTime != 2*256 ||
		bridge.ForwardDelay != 15*256 || bridge.UnknownMACDiscard != 1 ||
		bridge.MACLearningDepth != 64 || bridge.DynamicFilteringAgeTime != 600 {
		t.Fatalf("MAC bridge policy = %#v", bridge)
	}
	if bridge.Ports[0].Priority != 0x80 || bridge.Ports[0].PathCost != 10 ||
		bridge.Ports[0].SpanningTree != 1 || bridge.Ports[0].MACLearningDepth != 32 {
		t.Fatalf("MAC bridge port policy = %#v", bridge.Ports[0])
	}
	filter := graph.VLANFilters[0]
	if filter.TaggedAction != VLANFilterActionPositive ||
		filter.TaggedCriterion != VLANFilterCriterionVID ||
		filter.UntaggedAction != VLANFilterActionDiscard {
		t.Fatalf("VLAN filter policy = %#v", filter)
	}
	if got := graph.ExtendedVLANs[0].Rules; len(got) != 1 ||
		got[0].FilterOuter.Priority != 0 || got[0].TreatmentInner.Priority != 0 {
		t.Fatalf("extended VLAN rules = %#v, want one row", got)
	}
}

func TestBuildServiceGraphCombinesEthernetAdministrativeLocks(t *testing.T) {
	tests := []struct {
		name  string
		class me.ClassID
		id    uint16
		attr  string
	}{
		{name: "ONU", class: me.OnuGClassID, id: 0, attr: me.OnuG_AdministrativeState},
		{name: "circuit pack", class: me.CircuitPackClassID, id: 0x0101, attr: me.CircuitPack_AdministrativeState},
		{name: "Ethernet PPTP", class: me.PhysicalPathTerminationPointEthernetUniClassID, id: testUNI,
			attr: me.PhysicalPathTerminationPointEthernetUni_AdministrativeState},
		{name: "UNI-G", class: me.UniGClassID, id: testUNI, attr: me.UniG_AdministrativeState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validServiceSnapshot()
			snapshot = append(snapshot,
				mib.Instance{Key: mib.Key{ClassID: me.CircuitPackClassID, EntityID: 0x0101},
					Attributes: me.AttributeValueMap{me.CircuitPack_AdministrativeState: uint8(0)}},
				mib.Instance{Key: mib.Key{ClassID: me.UniGClassID, EntityID: testUNI},
					Attributes: me.AttributeValueMap{me.UniG_AdministrativeState: uint8(0)}},
			)
			findInstance(snapshot, test.class, test.id).Attributes[test.attr] = uint8(1)
			graph, err := BuildServiceGraph(snapshot)
			if err != nil {
				t.Fatalf("BuildServiceGraph(locked) error = %v", err)
			}
			if got := graph.UNIs[0].AdministrativeState; got != 1 {
				t.Fatalf("effective administrative state = %d, want locked", got)
			}

			findInstance(snapshot, test.class, test.id).Attributes[test.attr] = uint8(0)
			graph, err = BuildServiceGraph(snapshot)
			if err != nil {
				t.Fatalf("BuildServiceGraph(unlocked) error = %v", err)
			}
			if got := graph.UNIs[0].AdministrativeState; got != 0 {
				t.Fatalf("effective administrative state = %d, want unlocked", got)
			}
		})
	}
}

func TestBuildServiceGraphAllowsMultipleBridgeProfiles(t *testing.T) {
	const (
		secondUNI        = 0x0102
		secondBridge     = 0x0101
		secondBridgeIW   = 0x0302
		secondBridgeGEM  = 0x0402
		secondUNIPort    = 0x0503
		secondBridgePort = 0x0504
	)
	snapshot := validServiceSnapshot()
	snapshot = append(snapshot,
		mib.Instance{
			Key: mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: secondUNI},
			Attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_AdministrativeState: uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_OperationalState:    uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd:    uint8(4),
			},
		},
		mib.Instance{
			Key: mib.Key{ClassID: me.MacBridgeServiceProfileClassID, EntityID: secondBridge},
			Attributes: me.AttributeValueMap{
				me.MacBridgeServiceProfile_SpanningTreeInd:          uint8(0),
				me.MacBridgeServiceProfile_LearningInd:              uint8(1),
				me.MacBridgeServiceProfile_PortBridgingInd:          uint8(0),
				me.MacBridgeServiceProfile_Priority:                 uint16(0x8000),
				me.MacBridgeServiceProfile_MaxAge:                   uint16(20 * 256),
				me.MacBridgeServiceProfile_HelloTime:                uint16(2 * 256),
				me.MacBridgeServiceProfile_ForwardDelay:             uint16(15 * 256),
				me.MacBridgeServiceProfile_UnknownMacAddressDiscard: uint8(0),
			},
		},
		gemPortInstance(secondBridgeGEM, 202),
		gemIWInstance(secondBridgeIW, secondBridgeGEM, 1, secondBridge),
	)
	uniPort := bridgePortInstance(secondUNIPort, 1, 1, secondUNI)
	uniPort.Attributes[me.MacBridgePortConfigurationData_BridgeIdPointer] = uint16(secondBridge)
	aniPort := bridgePortInstance(secondBridgePort, 2, 5, secondBridgeIW)
	aniPort.Attributes[me.MacBridgePortConfigurationData_BridgeIdPointer] = uint16(secondBridge)
	snapshot = append(snapshot, uniPort, aniPort)

	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.Bridges) != 2 || graph.Bridges[0].EntityID != testBridge ||
		graph.Bridges[1].EntityID != secondBridge || len(graph.Bridges[1].Ports) != 2 {
		t.Fatalf("multi-profile bridges = %#v", graph.Bridges)
	}
	if len(graph.UNIs) != 2 || graph.UNIs[1].EntityID != secondUNI ||
		len(graph.GEMPorts) != 3 || len(graph.Interworking) != 3 {
		t.Fatalf("multi-profile service graph = %#v", graph)
	}
}

func TestBuildServiceGraphResolvesMulticastGEMAndSubscriber(t *testing.T) {
	const (
		multicastIW      = 0x0302
		multicastPort    = 0x0503
		multicastProfile = 0x0700
	)
	snapshot := validServiceSnapshot()
	ipv4 := make([]byte, 12)
	binary.BigEndian.PutUint16(ipv4[0:2], 202)
	binary.BigEndian.PutUint16(ipv4[2:4], 7)
	binary.BigEndian.PutUint32(ipv4[4:8], 0xe1000000)
	binary.BigEndian.PutUint32(ipv4[8:12], 0xe10000ff)
	ipv6 := make([]byte, 24)
	binary.BigEndian.PutUint16(ipv6[0:2], 203)
	binary.BigEndian.PutUint16(ipv6[2:4], 8)
	binary.BigEndian.PutUint32(ipv6[4:8], 0x100)
	binary.BigEndian.PutUint32(ipv6[8:12], 0x1ff)
	ipv6[12] = 0xff
	ipv6[13] = 0x3e
	dynamicACL := make([]byte, 3*24)
	binary.BigEndian.PutUint16(dynamicACL[0:2], 9)
	binary.BigEndian.PutUint16(dynamicACL[2:4], 203)
	binary.BigEndian.PutUint16(dynamicACL[4:6], 100)
	binary.BigEndian.PutUint32(dynamicACL[6:10], 1)
	binary.BigEndian.PutUint32(dynamicACL[10:14], 0x100)
	binary.BigEndian.PutUint32(dynamicACL[14:18], 0x1ff)
	binary.BigEndian.PutUint32(dynamicACL[18:22], 2_000_000)
	binary.BigEndian.PutUint16(dynamicACL[24:26], 1<<11|9)
	copy(dynamicACL[26:38], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(dynamicACL[38:40], 60)
	binary.BigEndian.PutUint16(dynamicACL[40:42], 3600)
	binary.BigEndian.PutUint16(dynamicACL[42:44], 2)
	binary.BigEndian.PutUint16(dynamicACL[44:46], 3)
	binary.BigEndian.PutUint16(dynamicACL[48:50], 2<<11|9)
	copy(dynamicACL[50:62], []byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	staticACL := make([]byte, 24)
	binary.BigEndian.PutUint16(staticACL[0:2], 10)
	binary.BigEndian.PutUint16(staticACL[2:4], 202)
	binary.BigEndian.PutUint16(staticACL[4:6], 0xffff)
	binary.BigEndian.PutUint32(staticACL[10:14], 0xe2000000)
	binary.BigEndian.PutUint32(staticACL[14:18], 0xe20000ff)
	servicePackage := make([]byte, 20)
	binary.BigEndian.PutUint16(servicePackage[0:2], 5)
	binary.BigEndian.PutUint16(servicePackage[2:4], 4096)
	binary.BigEndian.PutUint16(servicePackage[4:6], 8)
	binary.BigEndian.PutUint32(servicePackage[6:10], 8_000_000)
	binary.BigEndian.PutUint16(servicePackage[10:12], multicastProfile)
	allowedPreview := make([]byte, 44)
	binary.BigEndian.PutUint16(allowedPreview[0:2], 6)
	copy(allowedPreview[14:18], []byte{192, 0, 2, 10})
	binary.BigEndian.PutUint16(allowedPreview[18:20], 100)
	binary.BigEndian.PutUint16(allowedPreview[20:22], 200)
	binary.BigEndian.PutUint16(allowedPreview[22:24], 1<<11|6)
	copy(allowedPreview[36:40], []byte{239, 1, 2, 3})
	binary.BigEndian.PutUint16(allowedPreview[40:42], 30)
	binary.BigEndian.PutUint16(allowedPreview[42:44], 25)
	snapshot = append(snapshot,
		mib.Instance{
			Key: mib.Key{ClassID: me.MulticastGemInterworkingTerminationPointClassID,
				EntityID: multicastIW},
			Attributes: me.AttributeValueMap{
				me.MulticastGemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: uint16(testBridgeGEM),
				me.MulticastGemInterworkingTerminationPoint_InterworkingOption:                   uint8(1),
				me.MulticastGemInterworkingTerminationPoint_ServiceProfilePointer:                uint16(testBridge),
				me.MulticastGemInterworkingTerminationPoint_NotUsed1:                             uint16(0),
				me.MulticastGemInterworkingTerminationPoint_GalProfilePointer:                    uint16(testGAL),
				me.MulticastGemInterworkingTerminationPoint_NotUsed2:                             uint8(0),
				me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable: me.TableRows{
					NumRows: 1, Rows: ipv4,
				},
				me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable: me.TableRows{
					NumRows: 1, Rows: ipv6,
				},
			},
		},
		bridgePortInstance(multicastPort, 4, 6, multicastIW),
		mib.Instance{
			Key: mib.Key{ClassID: me.MulticastOperationsProfileClassID, EntityID: multicastProfile},
			Attributes: me.AttributeValueMap{
				me.MulticastOperationsProfile_IgmpVersion:            uint8(3),
				me.MulticastOperationsProfile_IgmpFunction:           uint8(0),
				me.MulticastOperationsProfile_ImmediateLeave:         uint8(1),
				me.MulticastOperationsProfile_UpstreamIgmpTci:        uint16(0),
				me.MulticastOperationsProfile_UpstreamIgmpTagControl: uint8(0),
				me.MulticastOperationsProfile_UpstreamIgmpRate:       uint32(0),
				me.MulticastOperationsProfile_DynamicAccessControlListTable: me.TableRows{
					NumRows: 3, Rows: dynamicACL,
				},
				me.MulticastOperationsProfile_StaticAccessControlListTable: me.TableRows{
					NumRows: 1, Rows: staticACL,
				},
				me.MulticastOperationsProfile_DownstreamIgmpAndMulticastTci:    []byte{0, 0, 0},
				me.MulticastOperationsProfile_UnauthorizedJoinRequestBehaviour: uint8(0),
			},
		},
		mib.Instance{
			Key: mib.Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: uniBridgePort},
			Attributes: me.AttributeValueMap{
				me.MulticastSubscriberConfigInfo_MeType:                            uint8(0),
				me.MulticastSubscriberConfigInfo_MulticastOperationsProfilePointer: uint16(multicastProfile),
				me.MulticastSubscriberConfigInfo_MaxSimultaneousGroups:             uint16(64),
				me.MulticastSubscriberConfigInfo_MaxMulticastBandwidth:             uint32(0),
				me.MulticastSubscriberConfigInfo_BandwidthEnforcement:              uint8(0),
				me.MulticastSubscriberConfigInfo_MulticastServicePackageTable: me.TableRows{
					NumRows: 1, Rows: servicePackage,
				},
				me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable: me.TableRows{
					NumRows: 2, Rows: allowedPreview,
				},
			},
		},
	)

	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.MulticastInterworking) != 1 || len(graph.MulticastProfiles) != 1 ||
		len(graph.MulticastSubscribers) != 1 || len(graph.Bridges[0].Ports) != 4 {
		t.Fatalf("multicast service graph = %#v", graph)
	}
	iw := graph.MulticastInterworking[0]
	if iw.EntityID != multicastIW || iw.GEMPort != testBridgeGEM || iw.PortID != 201 ||
		iw.AllocID != 100 || len(iw.IPv4Ranges) != 1 || len(iw.IPv6Ranges) != 1 ||
		iw.IPv4Ranges[0].GEMPortID != 202 || iw.IPv4Ranges[0].Start != "225.0.0.0" ||
		iw.IPv4Ranges[0].Stop != "225.0.0.255" || iw.IPv6Ranges[0].GEMPortID != 203 ||
		iw.IPv6Ranges[0].Start != "ff3e::100" || iw.IPv6Ranges[0].Stop != "ff3e::1ff" {
		t.Fatalf("multicast GEM IW = %#v", iw)
	}
	profile := graph.MulticastProfiles[0]
	if profile.IGMPVersion != 3 || profile.ImmediateLeave != 1 ||
		len(profile.DynamicACL) != 1 || len(profile.StaticACL) != 1 ||
		profile.DynamicACL[0].RowKey != 9 || profile.DynamicACL[0].IPVersion != 6 ||
		profile.DynamicACL[0].GEMPortID != 203 || profile.DynamicACL[0].Source != "2001:db8::1" ||
		profile.DynamicACL[0].Start != "ff3e::100" || profile.DynamicACL[0].Stop != "ff3e::1ff" ||
		profile.DynamicACL[0].ImputedBandwidth != 2_000_000 ||
		profile.DynamicACL[0].PreviewLength != 60 || profile.DynamicACL[0].PreviewResetTime != 3 ||
		profile.StaticACL[0].IPVersion != 4 || profile.StaticACL[0].Start != "226.0.0.0" ||
		profile.StaticACL[0].Stop != "226.0.0.255" ||
		graph.MulticastSubscribers[0].EntityID != uniBridgePort ||
		graph.MulticastSubscribers[0].MaxSimultaneousGroups != 64 ||
		len(graph.MulticastSubscribers[0].ServicePackages) != 1 ||
		graph.MulticastSubscribers[0].ServicePackages[0].RowKey != 5 ||
		graph.MulticastSubscribers[0].ServicePackages[0].OperationsProfile != multicastProfile ||
		len(graph.MulticastSubscribers[0].AllowedPreviewGroups) != 1 ||
		graph.MulticastSubscribers[0].AllowedPreviewGroups[0].Source != "192.0.2.10" ||
		graph.MulticastSubscribers[0].AllowedPreviewGroups[0].Destination != "239.1.2.3" ||
		graph.MulticastSubscribers[0].AllowedPreviewGroups[0].TimeLeft != 25 {
		t.Fatalf("multicast policy = %#v/%#v", graph.MulticastProfiles, graph.MulticastSubscribers)
	}
	policy, err := graph.MulticastPolicy()
	if err != nil {
		t.Fatalf("MulticastPolicy() error = %v", err)
	}
	if len(policy.Profiles) != 1 || len(policy.Subscribers) != 1 ||
		len(policy.Profiles[0].DynamicACL) != 1 ||
		policy.Profiles[0].DynamicACL[0].Start.String() != "ff3e::100" ||
		len(policy.Subscribers[0].Attachments) != 1 ||
		policy.Subscribers[0].Attachments[0].Interface != "lan1" ||
		policy.Subscribers[0].Attachments[0].BridgeEntity != testBridge ||
		policy.Subscribers[0].Attachments[0].BridgePortEntity != uniBridgePort {
		t.Fatalf("native multicast policy = %#v", policy)
	}
	if _, err := multicast.New(policy, nil); err != nil {
		t.Fatalf("native multicast policy validation error = %v", err)
	}
}

func TestMulticastPolicyResolvesDirectMapperUpstreamGEMs(t *testing.T) {
	mapper := PBitMapper{EntityID: testMapper, TPType: 1, TPPointer: testUNI,
		UnmarkedFrameOption: 1, DefaultPBit: 3}
	for priority := range mapper.PBits {
		mapper.PBits[priority] = testMapperIW
	}
	graph := ServiceGraph{
		UNIs:     []EthernetUNI{{EntityID: testUNI, Interface: "lan1"}},
		GEMPorts: []GEMPort{{EntityID: testMapperGEM, PortID: 200, Direction: 3}},
		Interworking: []GEMInterworking{{EntityID: testMapperIW, GEMPort: testMapperGEM,
			Option: 5, ServiceProfile: testMapper}},
		Mappers:           []PBitMapper{mapper},
		MulticastProfiles: []MulticastOperationsProfile{{EntityID: 0x700, IGMPVersion: 2}},
		MulticastSubscribers: []MulticastSubscriberConfigInfo{{
			EntityID: testMapper, METype: 1, Profile: 0x700,
		}},
	}
	policy, err := graph.MulticastPolicy()
	if err != nil {
		t.Fatalf("MulticastPolicy() error = %v", err)
	}
	if len(policy.Subscribers) != 1 || len(policy.Subscribers[0].Attachments) != 1 {
		t.Fatalf("direct mapper policy = %#v", policy)
	}
	attachment := policy.Subscribers[0].Attachments[0]
	if attachment.Interface != "lan1" || attachment.BridgeEntity != 0 ||
		attachment.DirectMapper == nil || attachment.DirectMapper.GEMPortIDs[0] != 200 ||
		attachment.DirectMapper.GEMPortIDs[7] != 200 || attachment.DirectMapper.DefaultPBit != 3 {
		t.Fatalf("direct mapper attachment = %#v", attachment)
	}
	backend := multicast.NewLinuxBackend(multicast.LinuxBackendOptions{Runner: &discardPlatformRunner{}})
	if _, err := multicast.NewRuntime(policy, backend, nil); err != nil {
		t.Fatalf("NewRuntime(direct mapper) error = %v", err)
	}

	graph.GEMPorts[0].Direction = 1
	if _, err := graph.MulticastPolicy(); err == nil || !strings.Contains(err.Error(), "upstream direction") {
		t.Fatalf("MulticastPolicy(downstream-only mapper GEM) error = %v", err)
	}
}

type discardPlatformRunner struct{}

func (*discardPlatformRunner) Run(string, ...string) error { return nil }

func TestBuildServiceGraphRejectsUnrepresentableMulticastReferences(t *testing.T) {
	const multicastIW = 0x0302
	base := func() []mib.Instance {
		snapshot := validServiceSnapshot()
		snapshot = append(snapshot, mib.Instance{
			Key: mib.Key{ClassID: me.MulticastGemInterworkingTerminationPointClassID,
				EntityID: multicastIW},
			Attributes: me.AttributeValueMap{
				me.MulticastGemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: uint16(testBridgeGEM),
				me.MulticastGemInterworkingTerminationPoint_InterworkingOption:                   uint8(1),
				me.MulticastGemInterworkingTerminationPoint_ServiceProfilePointer:                uint16(testBridge),
				me.MulticastGemInterworkingTerminationPoint_NotUsed1:                             uint16(0),
				me.MulticastGemInterworkingTerminationPoint_GalProfilePointer:                    uint16(0),
				me.MulticastGemInterworkingTerminationPoint_NotUsed2:                             uint8(0),
			},
		})
		return snapshot
	}
	tests := []struct {
		name string
		edit func([]mib.Instance) []mib.Instance
		want string
	}{
		{
			name: "upstream-only connectivity",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.GemPortNetworkCtpClassID, testBridgeGEM).
					Attributes[me.GemPortNetworkCtp_Direction] = uint8(2)
				return snapshot
			},
			want: "without downstream direction",
		},
		{
			name: "type 6 bridge mismatch",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.MulticastGemInterworkingTerminationPointClassID, multicastIW).
					Attributes[me.MulticastGemInterworkingTerminationPoint_ServiceProfilePointer] = uint16(0x7777)
				return append(snapshot, bridgePortInstance(0x0503, 4, 6, multicastIW))
			},
			want: "missing bridge profile",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildServiceGraph(test.edit(base()))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("BuildServiceGraph() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestBuildServiceGraphRejectsUnknownXG2010GUNI(t *testing.T) {
	snapshot := []mib.Instance{{
		Key: mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: 0x0201},
	}}
	_, err := BuildServiceGraph(snapshot)
	if err == nil || !strings.Contains(err.Error(), "no XG2010G interface mapping") {
		t.Fatalf("BuildServiceGraph() error = %v, want missing interface mapping", err)
	}
}

func TestBuildServiceGraphResolvesClassicVLANOperation(t *testing.T) {
	snapshot := withoutInstance(validServiceSnapshot(),
		me.ExtendedVlanTaggingOperationConfigurationDataClassID, 0x0600)
	snapshot = append(snapshot, mib.Instance{
		Key: mib.Key{ClassID: me.VlanTaggingOperationConfigurationDataClassID, EntityID: testUNI},
		Attributes: me.AttributeValueMap{
			me.VlanTaggingOperationConfigurationData_UpstreamVlanTaggingOperationMode:   uint8(2),
			me.VlanTaggingOperationConfigurationData_UpstreamVlanTagTciValue:            uint16(5<<13 | 1<<12 | 100),
			me.VlanTaggingOperationConfigurationData_DownstreamVlanTaggingOperationMode: uint8(1),
			me.VlanTaggingOperationConfigurationData_AssociationType:                    uint8(0),
		},
	})
	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.VLANOperations) != 1 {
		t.Fatalf("VLAN operations = %#v, want one", graph.VLANOperations)
	}
	operation := graph.VLANOperations[0]
	if operation.EntityID != testUNI || operation.AssociationType != 0 ||
		operation.AssociatedClass != me.PhysicalPathTerminationPointEthernetUniClassID ||
		operation.AssociatedME != testUNI || operation.UpstreamMode != 2 ||
		operation.UpstreamTCI != uint16(5<<13|1<<12|100) || operation.DownstreamMode != 1 {
		t.Fatalf("VLAN operation = %#v", operation)
	}
}

func TestBuildServiceGraphRejectsDuplicateVLANOperationAssociation(t *testing.T) {
	snapshot := append(validServiceSnapshot(), mib.Instance{
		Key: mib.Key{ClassID: me.VlanTaggingOperationConfigurationDataClassID, EntityID: testUNI},
		Attributes: me.AttributeValueMap{
			me.VlanTaggingOperationConfigurationData_UpstreamVlanTaggingOperationMode:   uint8(0),
			me.VlanTaggingOperationConfigurationData_UpstreamVlanTagTciValue:            uint16(0),
			me.VlanTaggingOperationConfigurationData_DownstreamVlanTaggingOperationMode: uint8(0),
			me.VlanTaggingOperationConfigurationData_AssociationType:                    uint8(0),
		},
	})
	if _, err := BuildServiceGraph(snapshot); err == nil || !strings.Contains(err.Error(), "share target") {
		t.Fatalf("BuildServiceGraph() error = %v, want duplicate VLAN operation target", err)
	}
}

func TestBuildServiceGraphIsDeterministic(t *testing.T) {
	snapshot := validServiceSnapshot()
	forward, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph(forward) error = %v", err)
	}
	for left, right := 0, len(snapshot)-1; left < right; left, right = left+1, right-1 {
		snapshot[left], snapshot[right] = snapshot[right], snapshot[left]
	}
	reversed, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph(reversed) error = %v", err)
	}
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("graph depends on snapshot order:\nforward=%#v\nreversed=%#v", forward, reversed)
	}
}

func TestValidateServiceGraphRejectsBrokenReferencesAndConstraints(t *testing.T) {
	tests := []struct {
		name string
		edit func([]mib.Instance) []mib.Instance
		want string
	}{
		{
			name: "dangling T-CONT",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return withoutInstance(snapshot, me.TContClassID, testTCONT)
			},
			want: "missing T-CONT",
		},
		{
			name: "dangling upstream traffic descriptor",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.GemPortNetworkCtpClassID, testMapperGEM).Attributes[me.GemPortNetworkCtp_TrafficDescriptorProfilePointerForUpstream] = uint16(0x7777)
				return snapshot
			},
			want: "missing upstream traffic descriptor",
		},
		{
			name: "dangling bridge port outbound traffic descriptor",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.MacBridgePortConfigurationDataClassID,
					uniBridgePort).Attributes[me.MacBridgePortConfigurationData_OutboundTdPointer] = uint16(0x7777)
				return snapshot
			},
			want: "missing outbound traffic descriptor",
		},
		{
			name: "dangling bridge port inbound traffic descriptor",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.MacBridgePortConfigurationDataClassID,
					uniBridgePort).Attributes[me.MacBridgePortConfigurationData_InboundTdPointer] = uint16(0x7777)
				return snapshot
			},
			want: "missing inbound traffic descriptor",
		},
		{
			name: "multiple schedulers serve one T-CONT",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				for _, entityID := range []uint16{0x9000, 0x9001} {
					snapshot = append(snapshot, mib.Instance{
						Key: mib.Key{ClassID: me.TrafficSchedulerClassID, EntityID: entityID},
						Attributes: me.AttributeValueMap{
							me.TrafficScheduler_TContPointer: uint16(testTCONT),
						},
					})
				}
				return snapshot
			},
			want: "is served by traffic schedulers",
		},
		{
			name: "duplicate T-CONT queue priority",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, mib.Instance{
					Key: mib.Key{ClassID: me.PriorityQueueClassID, EntityID: 0x8001},
					Attributes: me.AttributeValueMap{
						me.PriorityQueue_RelatedPort: uint32(testTCONT) << 16,
					},
				})
			},
			want: "more than one priority queue",
		},
		{
			name: "queue scheduler serves another T-CONT",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.PriorityQueueClassID, 0x8000).Attributes[me.PriorityQueue_TrafficSchedulerPointer] = uint16(0x9000)
				return append(snapshot, mib.Instance{
					Key: mib.Key{ClassID: me.TrafficSchedulerClassID, EntityID: 0x9000},
					Attributes: me.AttributeValueMap{
						me.TrafficScheduler_TContPointer: uint16(testTCONT + 1),
					},
				})
			},
			want: "serves T-CONT",
		},
		{
			name: "WRR without queue weight",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.TContClassID, testTCONT).Attributes[me.TCont_Policy] = uint8(2)
				findInstance(snapshot, me.PriorityQueueClassID, 0x8000).Attributes[me.PriorityQueue_Weight] = uint8(0)
				return snapshot
			},
			want: "WRR scheduler has no non-zero queue weight",
		},
		{
			name: "upstream queue belongs to UNI",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.PriorityQueueClassID, 0x8000).Attributes[me.PriorityQueue_RelatedPort] = uint32(testUNI) << 16
				return snapshot
			},
			want: "not T-CONT",
		},
		{
			name: "duplicate Alloc-ID",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, mib.Instance{
					Key:        mib.Key{ClassID: me.TContClassID, EntityID: testTCONT + 1},
					Attributes: me.AttributeValueMap{me.TCont_AllocId: uint16(100)},
				})
			},
			want: "Alloc-ID 100 is shared",
		},
		{
			name: "traffic descriptor CIR above PIR",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, trafficDescriptorInstance(0x8800, me.AttributeValueMap{
					me.TrafficDescriptor_Cir: uint32(2000),
					me.TrafficDescriptor_Pir: uint32(1000),
				}))
			},
			want: "above PIR",
		},
		{
			name: "reserved ingress colour marking",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, trafficDescriptorInstance(0x8800, me.AttributeValueMap{
					me.TrafficDescriptor_IngressColourMarking: uint8(1),
				}))
			},
			want: "invalid ingress colour marking",
		},
		{
			name: "invalid traffic descriptor meter type",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, trafficDescriptorInstance(0x8800, me.AttributeValueMap{
					me.TrafficDescriptor_MeterType: uint8(3),
				}))
			},
			want: "invalid meter type",
		},
		{
			name: "dangling mapper branch",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.Ieee8021PMapperServiceProfileClassID, testMapper).Attributes[me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority7] = uint16(0x7777)
				return snapshot
			},
			want: "P-bit 7 references missing GEM IW TP",
		},
		{
			name: "reserved unmarked frame option",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.Ieee8021PMapperServiceProfileClassID,
					testMapper).Attributes[me.Ieee8021PMapperServiceProfile_UnmarkedFrameOption] = uint8(2)
				return snapshot
			},
			want: "invalid unmarked frame option 2",
		},
		{
			name: "reserved default P-bit",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.Ieee8021PMapperServiceProfileClassID,
					testMapper).Attributes[me.Ieee8021PMapperServiceProfile_DefaultPBitAssumption] = uint8(8)
				return snapshot
			},
			want: "invalid default P-bit 8",
		},
		{
			name: "duplicate bridge port number",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.MacBridgePortConfigurationDataClassID, mapperPort).Attributes[me.MacBridgePortConfigurationData_PortNum] = uint8(1)
				return snapshot
			},
			want: "port number 1 is shared",
		},
		{
			name: "bridge GEM belongs to other profile",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.GemInterworkingTerminationPointClassID, testBridgeIW).Attributes[me.GemInterworkingTerminationPoint_ServiceProfilePointer] = uint16(0x7777)
				return snapshot
			},
			want: "missing bridge profile",
		},
		{
			name: "VLAN filter without implicit bridge port",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return withoutInstance(snapshot, me.MacBridgePortConfigurationDataClassID, uniBridgePort)
			},
			want: "no implicitly linked MAC bridge port",
		},
		{
			name: "reserved VLAN ID",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				list := make([]byte, 24)
				list[0], list[1] = 0x0f, 0xff
				findInstance(snapshot, me.VlanTaggingFilterDataClassID, uniBridgePort).Attributes[me.VlanTaggingFilterData_VlanFilterList] = list
				return snapshot
			},
			want: "reserved VID 4095",
		},
		{
			name: "dangling extended VLAN association",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				findInstance(snapshot, me.ExtendedVlanTaggingOperationConfigurationDataClassID, 0x0600).Attributes[me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer] = uint16(0x7777)
				return snapshot
			},
			want: "references missing",
		},
		{
			name: "reserved extended VLAN rule",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				table := findInstance(snapshot, me.ExtendedVlanTaggingOperationConfigurationDataClassID,
					0x0600).Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable].(me.TableRows)
				table.Rows[0] = 0x90
				return snapshot
			},
			want: "priority 9 is reserved",
		},
		{
			name: "delete GAL before GEM IW",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return withoutInstance(snapshot, me.GalEthernetProfileClassID, testGAL)
			},
			want: "missing GAL Ethernet profile",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateServiceGraph(test.edit(validServiceSnapshot()))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateServiceGraph() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestBuildServiceGraphExportsWRRScheduler(t *testing.T) {
	snapshot := validServiceSnapshot()
	findInstance(snapshot, me.PriorityQueueClassID, 0x8000).Attributes[me.PriorityQueue_TrafficSchedulerPointer] = uint16(0x9000)
	findInstance(snapshot, me.PriorityQueueClassID, 0x8000).Attributes[me.PriorityQueue_Weight] = uint8(5)
	snapshot = append(snapshot, mib.Instance{
		Key: mib.Key{ClassID: me.TrafficSchedulerClassID, EntityID: 0x9000},
		Attributes: me.AttributeValueMap{
			me.TrafficScheduler_TContPointer:   uint16(testTCONT),
			me.TrafficScheduler_Policy:         uint8(2),
			me.TrafficScheduler_PriorityWeight: uint8(9),
		},
	})
	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.TCONTs) != 1 || graph.TCONTs[0].SchedulerPolicy != 2 ||
		graph.TCONTs[0].SchedulerWeight != 9 || graph.TCONTs[0].QueueWeights[0] != 5 {
		t.Fatalf("T-CONT scheduler graph = %#v", graph.TCONTs)
	}
}

func TestBuildServiceGraphExportsTrafficDescriptor(t *testing.T) {
	snapshot := validServiceSnapshot()
	findInstance(snapshot, me.GemPortNetworkCtpClassID, testMapperGEM).Attributes[me.GemPortNetworkCtp_TrafficDescriptorProfilePointerForUpstream] = uint16(0x8800)
	bridgePort := findInstance(snapshot, me.MacBridgePortConfigurationDataClassID, uniBridgePort)
	bridgePort.Attributes[me.MacBridgePortConfigurationData_OutboundTdPointer] = uint16(0x8800)
	bridgePort.Attributes[me.MacBridgePortConfigurationData_InboundTdPointer] = uint16(0x8800)
	snapshot = append(snapshot, mib.Instance{
		Key: mib.Key{ClassID: me.TrafficDescriptorClassID, EntityID: 0x8800},
		Attributes: me.AttributeValueMap{
			me.TrafficDescriptor_Cir: uint32(1000),
			me.TrafficDescriptor_Pir: uint32(2000),
			me.TrafficDescriptor_Cbs: uint32(64),
			me.TrafficDescriptor_Pbs: uint32(128),
		},
	})
	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.TrafficDescs) != 1 || graph.TrafficDescs[0].EntityID != 0x8800 ||
		graph.TrafficDescs[0].CIR != 1000 || graph.GEMPorts[0].UpstreamTD != 0x8800 {
		t.Fatalf("traffic descriptor graph = %#v", graph)
	}
	if graph.Bridges[0].Ports[0].OutboundTD != 0x8800 ||
		graph.Bridges[0].Ports[0].InboundTD != 0x8800 {
		t.Fatalf("bridge port traffic descriptors = %#v", graph.Bridges[0].Ports[0])
	}
}

func TestBuildServiceGraphExportsDot1RateLimiter(t *testing.T) {
	snapshot := validServiceSnapshot()
	snapshot = append(snapshot,
		trafficDescriptorInstance(0x8800, me.AttributeValueMap{
			me.TrafficDescriptor_Pir: uint32(2000),
			me.TrafficDescriptor_Pbs: uint32(128),
		}),
		trafficDescriptorInstance(0x8801, me.AttributeValueMap{
			me.TrafficDescriptor_Pir: uint32(3000),
			me.TrafficDescriptor_Pbs: uint32(256),
		}),
		dot1RateLimiterInstance(0x8900, testBridge, 1, 0x8800, 0x8801, nullPointer),
	)
	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.Dot1RateLimiters) != 1 {
		t.Fatalf("dot1 rate limiter graph = %#v", graph.Dot1RateLimiters)
	}
	limiter := graph.Dot1RateLimiters[0]
	if limiter.EntityID != 0x8900 || limiter.ParentME != testBridge || limiter.TPType != 1 ||
		limiter.UpstreamUnicastFloodTD != 0x8800 || limiter.UpstreamBroadcastTD != 0x8801 ||
		limiter.UpstreamMulticastPayloadTD != nullPointer {
		t.Fatalf("dot1 rate limiter = %#v", limiter)
	}
}

func TestBuildServiceGraphExportsDirectMapperDot1RateLimiter(t *testing.T) {
	snapshot := withoutInstance(validServiceSnapshot(),
		me.MacBridgePortConfigurationDataClassID, mapperPort)
	mapper := findInstance(snapshot, me.Ieee8021PMapperServiceProfileClassID, testMapper)
	mapper.Attributes[me.Ieee8021PMapperServiceProfile_TpType] = uint8(1)
	mapper.Attributes[me.Ieee8021PMapperServiceProfile_TpPointer] = uint16(testUNI)
	findInstance(snapshot, me.GemInterworkingTerminationPointClassID,
		testMapperIW).Attributes[me.GemInterworkingTerminationPoint_InterworkingTerminationPointPointer] = uint16(testUNI)
	snapshot = append(snapshot,
		trafficDescriptorInstance(0x8800, me.AttributeValueMap{
			me.TrafficDescriptor_Pir: uint32(2000),
			me.TrafficDescriptor_Pbs: uint32(128),
		}),
		dot1RateLimiterInstance(0x8900, testMapper, 2, 0x8800, 0, 0),
	)
	graph, err := BuildServiceGraph(snapshot)
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	if len(graph.Dot1RateLimiters) != 1 {
		t.Fatalf("direct mapper dot1 rate limiter graph = %#v", graph.Dot1RateLimiters)
	}
	limiter := graph.Dot1RateLimiters[0]
	if limiter.ParentME != testMapper || limiter.TPType != 2 ||
		limiter.UpstreamUnicastFloodTD != 0x8800 ||
		limiter.UpstreamBroadcastTD != nullPointer ||
		limiter.UpstreamMulticastPayloadTD != nullPointer {
		t.Fatalf("direct mapper dot1 rate limiter = %#v", limiter)
	}
}

func TestBuildServiceGraphRejectsInvalidDot1RateLimiter(t *testing.T) {
	tests := []struct {
		name string
		edit func([]mib.Instance) []mib.Instance
		want string
	}{
		{
			name: "invalid TP type",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, dot1RateLimiterInstance(0x8900, testBridge, 3,
					nullPointer, nullPointer, nullPointer))
			},
			want: "invalid TP type 3",
		},
		{
			name: "missing parent",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, dot1RateLimiterInstance(0x8900, 0x7777, 1,
					nullPointer, nullPointer, nullPointer))
			},
			want: "references missing parent",
		},
		{
			name: "missing descriptor",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot, dot1RateLimiterInstance(0x8900, testBridge, 1,
					0x7777, nullPointer, nullPointer))
			},
			want: "missing upstream unknown-unicast flood traffic descriptor",
		},
		{
			name: "duplicate parent",
			edit: func(snapshot []mib.Instance) []mib.Instance {
				return append(snapshot,
					dot1RateLimiterInstance(0x8900, testBridge, 1,
						nullPointer, nullPointer, nullPointer),
					dot1RateLimiterInstance(0x8901, testBridge, 1,
						nullPointer, nullPointer, nullPointer))
			},
			want: "share parent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildServiceGraph(test.edit(validServiceSnapshot()))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("BuildServiceGraph() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateServiceGraphAllowsUnusedTCONTAndNullMapperBranches(t *testing.T) {
	snapshot := []mib.Instance{
		{
			Key:        mib.Key{ClassID: me.TContClassID, EntityID: testTCONT},
			Attributes: me.AttributeValueMap{me.TCont_AllocId: uint16(nullPointer)},
		},
		mapperInstance(testMapper, nullPointer),
	}
	if err := ValidateServiceGraph(snapshot); err != nil {
		t.Fatalf("ValidateServiceGraph() error = %v", err)
	}
}

func TestDecodeVLANForwardOperation(t *testing.T) {
	tests := []struct {
		operation uint8
		tagged    VLANFilterAction
		criterion VLANFilterCriterion
		untagged  VLANFilterAction
	}{
		{0x00, VLANFilterActionBridge, VLANFilterCriterionNone, VLANFilterActionBridge},
		{0x01, VLANFilterActionDiscard, VLANFilterCriterionNone, VLANFilterActionBridge},
		{0x02, VLANFilterActionBridge, VLANFilterCriterionNone, VLANFilterActionDiscard},
		{0x03, VLANFilterActionPositive, VLANFilterCriterionVID, VLANFilterActionBridge},
		{0x04, VLANFilterActionPositive, VLANFilterCriterionVID, VLANFilterActionDiscard},
		{0x05, VLANFilterActionNegative, VLANFilterCriterionVID, VLANFilterActionBridge},
		{0x06, VLANFilterActionNegative, VLANFilterCriterionVID, VLANFilterActionDiscard},
		{0x07, VLANFilterActionPositive, VLANFilterCriterionPriority, VLANFilterActionBridge},
		{0x08, VLANFilterActionPositive, VLANFilterCriterionPriority, VLANFilterActionDiscard},
		{0x09, VLANFilterActionNegative, VLANFilterCriterionPriority, VLANFilterActionBridge},
		{0x0a, VLANFilterActionNegative, VLANFilterCriterionPriority, VLANFilterActionDiscard},
		{0x0b, VLANFilterActionPositive, VLANFilterCriterionTCI, VLANFilterActionBridge},
		{0x0c, VLANFilterActionPositive, VLANFilterCriterionTCI, VLANFilterActionDiscard},
		{0x0d, VLANFilterActionNegative, VLANFilterCriterionTCI, VLANFilterActionBridge},
		{0x0e, VLANFilterActionNegative, VLANFilterCriterionTCI, VLANFilterActionDiscard},
		{0x0f, VLANFilterActionPositive, VLANFilterCriterionVID, VLANFilterActionBridge},
		{0x10, VLANFilterActionPositive, VLANFilterCriterionVID, VLANFilterActionDiscard},
		{0x11, VLANFilterActionPositive, VLANFilterCriterionPriority, VLANFilterActionBridge},
		{0x12, VLANFilterActionPositive, VLANFilterCriterionPriority, VLANFilterActionDiscard},
		{0x13, VLANFilterActionPositive, VLANFilterCriterionTCI, VLANFilterActionBridge},
		{0x14, VLANFilterActionPositive, VLANFilterCriterionTCI, VLANFilterActionDiscard},
		{0x15, VLANFilterActionBridge, VLANFilterCriterionNone, VLANFilterActionDiscard},
		{0x16, VLANFilterActionPositiveDA, VLANFilterCriterionVID, VLANFilterActionBridge},
		{0x17, VLANFilterActionPositiveDA, VLANFilterCriterionVID, VLANFilterActionDiscard},
		{0x18, VLANFilterActionPositiveDA, VLANFilterCriterionPriority, VLANFilterActionBridge},
		{0x19, VLANFilterActionPositiveDA, VLANFilterCriterionPriority, VLANFilterActionDiscard},
		{0x1a, VLANFilterActionPositiveDA, VLANFilterCriterionTCI, VLANFilterActionBridge},
		{0x1b, VLANFilterActionPositiveDA, VLANFilterCriterionTCI, VLANFilterActionDiscard},
		{0x1c, VLANFilterActionPositive, VLANFilterCriterionVID, VLANFilterActionBridge},
		{0x1d, VLANFilterActionPositive, VLANFilterCriterionVID, VLANFilterActionDiscard},
		{0x1e, VLANFilterActionPositive, VLANFilterCriterionPriority, VLANFilterActionBridge},
		{0x1f, VLANFilterActionPositive, VLANFilterCriterionPriority, VLANFilterActionDiscard},
		{0x20, VLANFilterActionPositive, VLANFilterCriterionTCI, VLANFilterActionBridge},
		{0x21, VLANFilterActionPositive, VLANFilterCriterionTCI, VLANFilterActionDiscard},
	}
	for _, test := range tests {
		tagged, criterion, untagged, err := decodeVLANForwardOperation(test.operation)
		if err != nil {
			t.Fatalf("decodeVLANForwardOperation(%#x) error = %v", test.operation, err)
		}
		if tagged != test.tagged || criterion != test.criterion || untagged != test.untagged {
			t.Errorf("decodeVLANForwardOperation(%#x) = %q/%q/%q, want %q/%q/%q",
				test.operation, tagged, criterion, untagged, test.tagged, test.criterion, test.untagged)
		}
	}
	for operation := 0x22; operation <= 0xff; operation++ {
		if _, _, _, err := decodeVLANForwardOperation(uint8(operation)); err == nil {
			t.Errorf("decodeVLANForwardOperation(%#x) accepted reserved operation", operation)
		}
	}
}

func TestBuildServiceGraphRejectsReservedVLANForwardOperation(t *testing.T) {
	snapshot := validServiceSnapshot()
	filter := findInstance(snapshot, me.VlanTaggingFilterDataClassID, uniBridgePort)
	filter.Attributes[me.VlanTaggingFilterData_ForwardOperation] = uint8(0x22)
	if _, err := BuildServiceGraph(snapshot); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("BuildServiceGraph() error = %v, want reserved forward operation", err)
	}
}

func TestBuildServiceGraphRejectsUnsupportedGALConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]mib.Instance)
		want   string
	}{
		{
			name: "payload size",
			mutate: func(snapshot []mib.Instance) {
				findInstance(snapshot, me.GalEthernetProfileClassID, testGAL).Attributes[me.GalEthernetProfile_MaximumGemPayloadSize] = uint16(64)
			},
			want: "unsupported maximum GEM payload size 64",
		},
		{
			name: "loopback",
			mutate: func(snapshot []mib.Instance) {
				findInstance(snapshot, me.GemInterworkingTerminationPointClassID, testMapperIW).Attributes[me.GemInterworkingTerminationPoint_GalLoopbackConfiguration] = uint8(1)
			},
			want: "unsupported GAL loopback mode 1",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validServiceSnapshot()
			test.mutate(snapshot)
			_, err := BuildServiceGraph(snapshot)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("BuildServiceGraph() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOLTCanBuildServiceGraphTransactionByTransaction(t *testing.T) {
	factory, err := model.XG2010G(model.Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatalf("model.XG2010G() error = %v", err)
	}
	store, err := mib.NewWithApplier(factory, mib.ApplyFunc(func(change mib.Change) error {
		return ValidateServiceGraph(change.Snapshot)
	}))
	if err != nil {
		t.Fatalf("mib.NewWithApplier() error = %v", err)
	}

	mustSet(t, store, mib.Key{ClassID: me.TContClassID, EntityID: testTCONT}, me.AttributeValueMap{
		me.TCont_AllocId: uint16(100),
	})
	mustCreate(t, store, me.GalEthernetProfileClassID, testGAL, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	})
	mustCreate(t, store, me.MacBridgeServiceProfileClassID, testBridge, me.AttributeValueMap{
		me.MacBridgeServiceProfile_SpanningTreeInd:          uint8(0),
		me.MacBridgeServiceProfile_LearningInd:              uint8(1),
		me.MacBridgeServiceProfile_PortBridgingInd:          uint8(0),
		me.MacBridgeServiceProfile_Priority:                 uint16(0x8000),
		me.MacBridgeServiceProfile_MaxAge:                   uint16(20 * 256),
		me.MacBridgeServiceProfile_HelloTime:                uint16(2 * 256),
		me.MacBridgeServiceProfile_ForwardDelay:             uint16(15 * 256),
		me.MacBridgeServiceProfile_UnknownMacAddressDiscard: uint8(0),
	})
	mapperAttributes := mapperInstance(testMapper, nullPointer).Attributes
	mustCreate(t, store, me.Ieee8021PMapperServiceProfileClassID, testMapper, mapperAttributes)
	mustCreate(t, store, me.GemPortNetworkCtpClassID, testMapperGEM,
		gemPortInstance(testMapperGEM, 200).Attributes)
	mustCreate(t, store, me.GemInterworkingTerminationPointClassID, testMapperIW,
		gemIWInstance(testMapperIW, testMapperGEM, 5, testMapper).Attributes)

	mapperBranches := make(me.AttributeValueMap, len(mapperPBitAttributes))
	for _, name := range mapperPBitAttributes {
		mapperBranches[name] = uint16(testMapperIW)
	}
	mustSet(t, store, mib.Key{ClassID: me.Ieee8021PMapperServiceProfileClassID, EntityID: testMapper}, mapperBranches)
	mustCreate(t, store, me.MacBridgePortConfigurationDataClassID, uniBridgePort,
		bridgePortInstance(uniBridgePort, 1, 1, testUNI).Attributes)
	mustCreate(t, store, me.MacBridgePortConfigurationDataClassID, mapperPort,
		bridgePortInstance(mapperPort, 2, 3, testMapper).Attributes)

	vlanList := make([]byte, 24)
	vlanList[1] = 100
	mustCreate(t, store, me.VlanTaggingFilterDataClassID, uniBridgePort, me.AttributeValueMap{
		me.VlanTaggingFilterData_VlanFilterList:   vlanList,
		me.VlanTaggingFilterData_ForwardOperation: uint8(0x10),
		me.VlanTaggingFilterData_NumberOfEntries:  uint8(1),
	})
	mustCreate(t, store, me.ExtendedVlanTaggingOperationConfigurationDataClassID, 0x0600, me.AttributeValueMap{
		me.ExtendedVlanTaggingOperationConfigurationData_AssociationType:     uint8(2),
		me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer: uint16(testUNI),
	})

	graph, err := BuildServiceGraph(store.Snapshot())
	if err != nil {
		t.Fatalf("BuildServiceGraph(final MIB) error = %v", err)
	}
	if len(graph.GEMPorts) != 1 || len(graph.Interworking) != 1 ||
		len(graph.Mappers) != 1 || len(graph.Bridges) != 1 ||
		len(graph.Bridges[0].Ports) != 2 || len(graph.VLANFilters) != 1 ||
		len(graph.ExtendedVLANs) != 1 {
		t.Fatalf("final graph = %#v", graph)
	}
}

func validServiceSnapshot() []mib.Instance {
	vlanList := make([]byte, 24)
	vlanList[1] = 100
	mapper := mapperInstance(testMapper, testMapperIW)
	return []mib.Instance{
		{
			Key: mib.Key{ClassID: me.OnuGClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuG_TrafficManagementOption: uint8(0),
			},
		},
		{
			Key: mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: testUNI},
			Attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_AdministrativeState: uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_OperationalState:    uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd:    uint8(4),
			},
		},
		{
			Key:        mib.Key{ClassID: me.TContClassID, EntityID: testTCONT},
			Attributes: me.AttributeValueMap{me.TCont_AllocId: uint16(100)},
		},
		{
			Key: mib.Key{ClassID: me.PriorityQueueClassID, EntityID: 0x8000},
			Attributes: me.AttributeValueMap{
				me.PriorityQueue_RelatedPort: uint32(testTCONT) << 16,
			},
		},
		{
			Key: mib.Key{ClassID: me.PriorityQueueClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.PriorityQueue_RelatedPort: uint32(testUNI) << 16,
			},
		},
		{
			Key: mib.Key{ClassID: me.GalEthernetProfileClassID, EntityID: testGAL},
			Attributes: me.AttributeValueMap{
				me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
			},
		},
		{
			Key: mib.Key{ClassID: me.MacBridgeServiceProfileClassID, EntityID: testBridge},
			Attributes: me.AttributeValueMap{
				me.MacBridgeServiceProfile_SpanningTreeInd:            uint8(1),
				me.MacBridgeServiceProfile_LearningInd:                uint8(1),
				me.MacBridgeServiceProfile_PortBridgingInd:            uint8(1),
				me.MacBridgeServiceProfile_Priority:                   uint16(0x9000),
				me.MacBridgeServiceProfile_MaxAge:                     uint16(20 * 256),
				me.MacBridgeServiceProfile_HelloTime:                  uint16(2 * 256),
				me.MacBridgeServiceProfile_ForwardDelay:               uint16(15 * 256),
				me.MacBridgeServiceProfile_UnknownMacAddressDiscard:   uint8(1),
				me.MacBridgeServiceProfile_MacLearningDepth:           uint8(64),
				me.MacBridgeServiceProfile_DynamicFilteringAgeingTime: uint32(600),
			},
		},
		mapper,
		gemPortInstance(testMapperGEM, 200),
		gemPortInstance(testBridgeGEM, 201),
		gemIWInstance(testMapperIW, testMapperGEM, 5, testMapper),
		gemIWInstance(testBridgeIW, testBridgeGEM, 1, testBridge),
		bridgePortInstance(uniBridgePort, 1, 1, testUNI),
		bridgePortInstance(mapperPort, 2, 3, testMapper),
		bridgePortInstance(gemBridgePort, 3, 5, testBridgeIW),
		{
			Key: mib.Key{ClassID: me.VlanTaggingFilterDataClassID, EntityID: uniBridgePort},
			Attributes: me.AttributeValueMap{
				me.VlanTaggingFilterData_VlanFilterList:   vlanList,
				me.VlanTaggingFilterData_ForwardOperation: uint8(0x10),
				me.VlanTaggingFilterData_NumberOfEntries:  uint8(1),
			},
		},
		{
			Key: mib.Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: 0x0600},
			Attributes: me.AttributeValueMap{
				me.ExtendedVlanTaggingOperationConfigurationData_AssociationType:                               uint8(2),
				me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer:                           uint16(testUNI),
				me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize: uint16(64),
				me.ExtendedVlanTaggingOperationConfigurationData_InputTpid:                                     uint16(0x8100),
				me.ExtendedVlanTaggingOperationConfigurationData_OutputTpid:                                    uint16(0x8100),
				me.ExtendedVlanTaggingOperationConfigurationData_DownstreamMode:                                uint8(0),
				me.ExtendedVlanTaggingOperationConfigurationData_EnhancedMode:                                  uint8(0),
				me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable: me.TableRows{
					NumRows: 1,
					Rows:    make([]byte, 16),
				},
			},
		},
	}
}

func mapperInstance(entityID, branch uint16) mib.Instance {
	attributes := me.AttributeValueMap{
		me.Ieee8021PMapperServiceProfile_TpPointer:             uint16(nullPointer),
		me.Ieee8021PMapperServiceProfile_UnmarkedFrameOption:   uint8(1),
		me.Ieee8021PMapperServiceProfile_DefaultPBitAssumption: uint8(0),
		me.Ieee8021PMapperServiceProfile_TpType:                uint8(0),
	}
	for _, name := range mapperPBitAttributes {
		attributes[name] = branch
	}
	return mib.Instance{
		Key:        mib.Key{ClassID: me.Ieee8021PMapperServiceProfileClassID, EntityID: entityID},
		Attributes: attributes,
	}
}

func gemPortInstance(entityID, portID uint16) mib.Instance {
	return mib.Instance{
		Key: mib.Key{ClassID: me.GemPortNetworkCtpClassID, EntityID: entityID},
		Attributes: me.AttributeValueMap{
			me.GemPortNetworkCtp_PortId:                              portID,
			me.GemPortNetworkCtp_TContPointer:                        uint16(testTCONT),
			me.GemPortNetworkCtp_Direction:                           uint8(3),
			me.GemPortNetworkCtp_TrafficManagementPointerForUpstream: uint16(0x8000),
			me.GemPortNetworkCtp_PriorityQueuePointerForDownStream:   uint16(0),
		},
	}
}

func trafficDescriptorInstance(entityID uint16, attributes me.AttributeValueMap) mib.Instance {
	return mib.Instance{
		Key:        mib.Key{ClassID: me.TrafficDescriptorClassID, EntityID: entityID},
		Attributes: attributes,
	}
}

func dot1RateLimiterInstance(entityID, parent uint16, tpType uint8,
	unknown, broadcast, multicast uint16) mib.Instance {
	return mib.Instance{
		Key: mib.Key{ClassID: me.Dot1RateLimiterClassID, EntityID: entityID},
		Attributes: me.AttributeValueMap{
			me.Dot1RateLimiter_ParentMePointer:                     parent,
			me.Dot1RateLimiter_TpType:                              tpType,
			me.Dot1RateLimiter_UpstreamUnicastFloodRatePointer:     unknown,
			me.Dot1RateLimiter_UpstreamBroadcastRatePointer:        broadcast,
			me.Dot1RateLimiter_UpstreamMulticastPayloadRatePointer: multicast,
		},
	}
}

func gemIWInstance(entityID, gemPort uint16, option uint8, service uint16) mib.Instance {
	return mib.Instance{
		Key: mib.Key{ClassID: me.GemInterworkingTerminationPointClassID, EntityID: entityID},
		Attributes: me.AttributeValueMap{
			me.GemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: gemPort,
			me.GemInterworkingTerminationPoint_InterworkingOption:                   option,
			me.GemInterworkingTerminationPoint_ServiceProfilePointer:                service,
			me.GemInterworkingTerminationPoint_InterworkingTerminationPointPointer:  uint16(0),
			me.GemInterworkingTerminationPoint_GalProfilePointer:                    uint16(testGAL),
		},
	}
}

func bridgePortInstance(entityID uint16, port, tpType uint8, tp uint16) mib.Instance {
	return mib.Instance{
		Key: mib.Key{ClassID: me.MacBridgePortConfigurationDataClassID, EntityID: entityID},
		Attributes: me.AttributeValueMap{
			me.MacBridgePortConfigurationData_BridgeIdPointer:     uint16(testBridge),
			me.MacBridgePortConfigurationData_PortNum:             port,
			me.MacBridgePortConfigurationData_TpType:              tpType,
			me.MacBridgePortConfigurationData_TpPointer:           tp,
			me.MacBridgePortConfigurationData_PortPriority:        uint16(0x80),
			me.MacBridgePortConfigurationData_PortPathCost:        uint16(10),
			me.MacBridgePortConfigurationData_PortSpanningTreeInd: uint8(1),
			me.MacBridgePortConfigurationData_MacLearningDepth:    uint8(32),
		},
	}
}

func findInstance(snapshot []mib.Instance, classID me.ClassID, entityID uint16) *mib.Instance {
	for index := range snapshot {
		if snapshot[index].ClassID == classID && snapshot[index].EntityID == entityID {
			return &snapshot[index]
		}
	}
	panic("test instance not found")
}

func withoutInstance(snapshot []mib.Instance, classID me.ClassID, entityID uint16) []mib.Instance {
	filtered := make([]mib.Instance, 0, len(snapshot)-1)
	for _, instance := range snapshot {
		if instance.ClassID != classID || instance.EntityID != entityID {
			filtered = append(filtered, instance)
		}
	}
	return filtered
}

func mustCreate(t *testing.T, store *mib.Store, classID me.ClassID, entityID uint16,
	attributes me.AttributeValueMap) {
	t.Helper()
	if err := store.Create(classID, entityID, attributes); err != nil {
		t.Fatalf("Create(%d/%#x) error = %v", classID, entityID, err)
	}
}

func mustSet(t *testing.T, store *mib.Store, key mib.Key, attributes me.AttributeValueMap) {
	t.Helper()
	if err := store.Set(key, attributes); err != nil {
		t.Fatalf("Set(%d/%#x) error = %v", key.ClassID, key.EntityID, err)
	}
}

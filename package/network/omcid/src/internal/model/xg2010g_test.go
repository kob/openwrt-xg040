// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"slices"
	"strings"
	"testing"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

func TestXG2010GFactoryMIB(t *testing.T) {
	factory, err := XG2010G(Identity{SerialNumber: "ABCD01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatalf("XG2010G() error = %v", err)
	}
	store, err := mib.New(factory)
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}

	var ethernetUNIs int
	var tconts int
	var schedulers int
	var queues int
	configurations := make(map[uint16]uint8)
	sensedTypes := make(map[uint16]uint8)
	var ani mib.Instance
	var onu mib.Instance
	var onu2 mib.Instance
	var onu3Instance mib.Instance
	cardholders := make(map[uint16]mib.Instance)
	circuitPacks := make(map[uint16]mib.Instance)
	for _, item := range store.Snapshot() {
		switch item.ClassID {
		case me.OnuGClassID:
			onu = item
		case me.AniGClassID:
			ani = item
		case me.Onu2GClassID:
			onu2 = item
		case me.Onu3GClassID:
			onu3Instance = item
		case me.CardholderClassID:
			cardholders[item.EntityID] = item
		case me.CircuitPackClassID:
			circuitPacks[item.EntityID] = item
		case me.PhysicalPathTerminationPointEthernetUniClassID:
			ethernetUNIs++
			configurations[item.EntityID] = item.Attributes[me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd].(uint8)
			sensedTypes[item.EntityID] = item.Attributes[me.PhysicalPathTerminationPointEthernetUni_SensedType].(uint8)
		case me.TContClassID:
			tconts++
		case me.TrafficSchedulerClassID:
			schedulers++
		case me.PriorityQueueClassID:
			queues++
		}
	}
	if ani.EntityID != aniEntityID || ani.Attributes[me.AniG_Arc] != uint8(0) ||
		ani.Attributes[me.AniG_ArcInterval] != uint8(0) ||
		ani.Attributes[me.AniG_LowerOpticalThreshold] != uint8(0xff) ||
		ani.Attributes[me.AniG_UpperOpticalThreshold] != uint8(0xff) ||
		ani.Attributes[me.AniG_LowerTransmitPowerThreshold] != uint8(0x81) ||
		ani.Attributes[me.AniG_UpperTransmitPowerThreshold] != uint8(0x81) {
		t.Fatalf("ANI-G defaults = %#v", ani)
	}
	if ethernetUNIs != 4 {
		t.Fatalf("Ethernet UNI count = %d, want 4", ethernetUNIs)
	}
	if tconts != defaultTContCount {
		t.Fatalf("T-CONT count = %d, want %d", tconts, defaultTContCount)
	}
	if schedulers != defaultTContCount {
		t.Fatalf("traffic scheduler count = %d, want %d", schedulers, defaultTContCount)
	}
	wantQueues := (defaultTContCount + len(ethernetConfiguration)) * queuesPerPort
	if queues != wantQueues {
		t.Fatalf("priority queue count = %d, want %d", queues, wantQueues)
	}
	if onu.Attributes[me.OnuG_TrafficManagementOption] != uint8(0) {
		t.Fatalf("ONU-G traffic management option = %#v, want priority controlled",
			onu.Attributes[me.OnuG_TrafficManagementOption])
	}
	if onu2.Attributes[me.Onu2G_TotalPriorityQueueNumber] != uint16(0) ||
		onu2.Attributes[me.Onu2G_TotalTrafficSchedulerNumber] != uint8(0) {
		t.Fatalf("ONU2-G global QoS resources = %#v, want no resources outside circuit packs", onu2.Attributes)
	}
	if onu2.Attributes[me.Onu2G_ConnectivityCapability] != uint16(0) ||
		onu2.Attributes[me.Onu2G_CurrentConnectivityMode] != uint8(0) ||
		onu2.Attributes[me.Onu2G_QualityOfServiceQosConfigurationFlexibility] != uint16(0x0008) {
		t.Fatalf("ONU2-G connectivity/QoS declarations = %#v", onu2.Attributes)
	}
	if onu3Instance.Attributes[me.Onu3G_TotalNumberOfStatusSnapshots] != uint16(16) ||
		onu3Instance.Attributes[me.Onu3G_NumberOfValidStatusSnapshots] != uint16(0) ||
		onu3Instance.Attributes[me.Onu3G_NextStatusSnapshotIndex] != uint16(0) ||
		onu3Instance.Attributes[me.Onu3G_EnhancedMode] != uint8(1) {
		t.Fatalf("ONU3-G defaults = %#v", onu3Instance.Attributes)
	}
	if table, valid := onu3Instance.Attributes[me.Onu3G_StatusSnapshotRecordTable].(me.TableRows); !valid || table.NumRows != 0 || len(table.Rows) != 0 {
		t.Fatalf("ONU3-G status table = %#v, want empty", onu3Instance.Attributes[me.Onu3G_StatusSnapshotRecordTable])
	}
	if got := circuitPacks[ethernetCardID].Attributes[me.CircuitPack_TotalPriorityQueueNumber]; got != uint8(len(ethernetConfiguration)*queuesPerPort) {
		t.Fatalf("Ethernet circuit-pack queues = %#v, want %d", got,
			len(ethernetConfiguration)*queuesPerPort)
	}
	for holderID, cardID := range map[uint16]uint16{
		ethernetHolderID: ethernetCardID,
		aniHolderID:      aniCardID,
	} {
		holder, holderPresent := cardholders[holderID]
		card, cardPresent := circuitPacks[cardID]
		if !holderPresent || !cardPresent || holderID != cardID ||
			holder.Attributes[me.Cardholder_ActualPlugInUnitType] != card.Attributes[me.CircuitPack_Type] ||
			holder.Attributes[me.Cardholder_ExpectedPlugInUnitType] != card.Attributes[me.CircuitPack_Type] {
			t.Fatalf("cardholder/circuit-pack topology %#x = %#v/%#v", holderID, holder, card)
		}
	}
	if uint8(ani.EntityID>>8) != uint8(aniCardID&0xff) {
		t.Fatalf("ANI-G slot %#x does not match circuit-pack slot %#x",
			ani.EntityID>>8, aniCardID&0xff)
	}
	if got := circuitPacks[ethernetCardID].Attributes[me.CircuitPack_TotalTContBufferNumber]; got != uint8(0) {
		t.Fatalf("Ethernet circuit-pack T-CONT buffers = %#v, want 0", got)
	}
	if got := circuitPacks[ethernetCardID].Attributes[me.CircuitPack_Type]; got != uint8(45) {
		t.Fatalf("Ethernet circuit-pack type = %#v, want mixed services equipment", got)
	}
	if got := circuitPacks[aniCardID].Attributes[me.CircuitPack_TotalPriorityQueueNumber]; got != uint8(defaultTContCount*queuesPerPort) {
		t.Fatalf("ANI circuit-pack queues = %#v, want %d", got, defaultTContCount*queuesPerPort)
	}
	if got := circuitPacks[aniCardID].Attributes[me.CircuitPack_TotalTrafficSchedulerNumber]; got != uint8(defaultTContCount) {
		t.Fatalf("ANI circuit-pack schedulers = %#v, want %d", got, defaultTContCount)
	}
	for index, want := range ethernetConfiguration {
		entityID := uint16(ethernetCardID + index)
		if got := configurations[entityID]; got != want {
			t.Fatalf("Ethernet UNI %#x configuration = %d, want %d", entityID, got, want)
		}
		if got := sensedTypes[entityID]; got != ethernetSensedType[index] {
			t.Fatalf("Ethernet UNI %#x sensed type = %d, want %d",
				entityID, got, ethernetSensedType[index])
		}
		uni, err := store.Get(mib.Key{ClassID: me.UniGClassID, EntityID: entityID}, 0xe000)
		if err != nil {
			t.Fatalf("Get(UNI-G %#x) error = %v", entityID, err)
		}
		if uni.Attributes[me.UniG_Deprecated] != uint16(0) ||
			uni.Attributes[me.UniG_ManagementCapability] != uint8(0) {
			t.Fatalf("UNI-G %#x attributes = %#v", entityID, uni.Attributes)
		}
	}
}

func TestXG2010GRejectsMalformedSerial(t *testing.T) {
	if _, err := XG2010G(Identity{SerialNumber: "bad", PONMode: pon.GPON}); err == nil {
		t.Fatal("XG2010G() error = nil, want malformed serial error")
	}
}

func TestXG2010GSupportedClassesAreExplicitAndSorted(t *testing.T) {
	classes := XG2010GSupportedClasses(pon.GPON)
	if !slices.IsSorted(classes) {
		t.Fatalf("supported classes are not sorted: %v", classes)
	}
	seen := make(map[me.ClassID]struct{}, len(classes))
	for _, classID := range classes {
		if _, duplicate := seen[classID]; duplicate {
			t.Fatalf("duplicate supported class %v", classID)
		}
		seen[classID] = struct{}{}
	}
	for _, required := range []me.ClassID{
		me.OmciClassID, me.ManagedEntityMeClassID, me.AttributeMeClassID,
		me.CardholderClassID,
		me.GemPortNetworkCtpClassID, me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		me.Dot1RateLimiterClassID,
		me.Onu3GClassID,
	} {
		if _, present := seen[required]; !present {
			t.Fatalf("supported classes omit %v", required)
		}
	}
	if _, present := seen[me.IpHostConfigDataClassID]; present {
		t.Fatalf("unsupported IP host class is advertised")
	}
}

func TestXG2010GCapabilitiesAreIsolatedByPONMode(t *testing.T) {
	xgsClasses := XG2010GSupportedClasses(pon.XGSPON)
	gponClasses := XG2010GSupportedClasses(pon.GPON)
	for _, classID := range []me.ClassID{
		me.XgPonTcPerformanceMonitoringHistoryDataClassID,
		me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID,
		me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID,
	} {
		if !slices.Contains(xgsClasses, classID) {
			t.Fatalf("XGS-PON capability list omits class %v", classID)
		}
		if slices.Contains(gponClasses, classID) {
			t.Fatalf("GPON capability list advertises XGS-PON class %v", classID)
		}
	}
	factory, err := XG2010G(Identity{SerialNumber: "TEST01020304", PONMode: pon.XGSPON})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := XG2010GSupportedAttributeMasks(pon.XGSPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	for classID, want := range map[me.ClassID]uint16{
		me.XgPonTcPerformanceMonitoringHistoryDataClassID:                   0xfffe,
		me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID: 0xffff,
		me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID:   0xff00,
	} {
		if masks[classID] != want {
			t.Fatalf("XGS-PON class %v mask = %#x, want %#x", classID, masks[classID], want)
		}
	}
}

func TestXG2010GAttributePolicyMatchesImplementedSurface(t *testing.T) {
	factory, err := XG2010G(Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := XG2010GSupportedAttributeMasks(pon.GPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	classes := XG2010GSupportedClasses(pon.GPON)
	if len(masks) != len(classes) {
		t.Fatalf("attribute policies = %d, supported classes = %d", len(masks), len(classes))
	}
	for _, classID := range classes {
		if mask, present := masks[classID]; !present || mask == 0 {
			t.Fatalf("class %v attribute mask = %#x/%t", classID, mask, present)
		}
	}
	for classID, want := range map[me.ClassID]uint16{
		me.GemInterworkingTerminationPointClassID:                   0xf300,
		me.GemPortNetworkCtpClassID:                                 0xfa80,
		me.MacBridgePortConfigurationDataClassID:                    0xfe38,
		me.TrafficDescriptorClassID:                                 0xf100,
		me.MulticastOperationsProfileClassID:                        0xff7f,
		me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID: 0xfc00,
	} {
		if got := masks[classID]; got != want {
			t.Fatalf("class %v attribute mask = %#x, want %#x", classID, got, want)
		}
	}

	store, err := mib.NewWithOptions(factory, mib.Options{
		SupportedClasses: XG2010GSupportedClasses(pon.GPON), SupportedAttributeMasks: masks,
		ValidateInstance:      XG2010GInstanceValidator(pon.GPON),
		AttributeCapabilities: XG2010GAttributeCapabilities(pon.GPON),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := mib.Key{ClassID: me.GemInterworkingTerminationPointClassID, EntityID: 0x100}
	if err := store.Create(key.ClassID, key.EntityID, me.AttributeValueMap{
		me.GemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: uint16(0x200),
		me.GemInterworkingTerminationPoint_InterworkingOption:                   uint8(1),
		me.GemInterworkingTerminationPoint_ServiceProfilePointer:                uint16(0x300),
		me.GemInterworkingTerminationPoint_InterworkingTerminationPointPointer:  uint16(0),
		me.GemInterworkingTerminationPoint_GalProfilePointer:                    uint16(1),
	}); err != nil {
		t.Fatalf("Create(GEM IW) error = %v", err)
	}
	created, err := store.Get(key, masks[key.ClassID])
	if err != nil {
		t.Fatalf("Get(GEM IW) error = %v", err)
	}
	for _, omitted := range []string{
		me.GemInterworkingTerminationPoint_PptpCounter,
		me.GemInterworkingTerminationPoint_OperationalState,
	} {
		if _, present := created.Attributes[omitted]; present {
			t.Fatalf("GEM IW snapshot retained unsupported default attribute %s", omitted)
		}
	}
	_, err = store.Get(key, 0x0800)
	var result *mib.ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.UnsupportedMask != 0x0800 {
		t.Fatalf("Get(unsupported GEM IW attribute) error = %#v", err)
	}

	err = store.Create(me.TrafficDescriptorClassID, 0x101, me.AttributeValueMap{
		me.TrafficDescriptor_ColourMode: uint8(0),
	})
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.UnsupportedMask != 0x0800 {
		t.Fatalf("Create(unadvertised colour mode) error = %#v", err)
	}
}

func TestXG2010GRejectsUnsupportedFixedAttributeValues(t *testing.T) {
	factory, err := XG2010G(Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := XG2010GSupportedAttributeMasks(pon.GPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := mib.NewWithOptions(factory, mib.Options{
		SupportedClasses: XG2010GSupportedClasses(pon.GPON), SupportedAttributeMasks: masks,
		ValidateInstance:      XG2010GInstanceValidator(pon.GPON),
		AttributeCapabilities: XG2010GAttributeCapabilities(pon.GPON),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		classID    me.ClassID
		entityID   uint16
		attributes me.AttributeValueMap
		failedMask uint16
	}{
		{
			name: "GAL payload", classID: me.GalEthernetProfileClassID, entityID: 1,
			attributes: me.AttributeValueMap{
				me.GalEthernetProfile_MaximumGemPayloadSize: uint16(64),
			}, failedMask: 0x8000,
		},
		{
			name: "GAL loopback", classID: me.GemInterworkingTerminationPointClassID, entityID: 2,
			attributes: me.AttributeValueMap{
				me.GemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: uint16(0x200),
				me.GemInterworkingTerminationPoint_InterworkingOption:                   uint8(1),
				me.GemInterworkingTerminationPoint_ServiceProfilePointer:                uint16(0x300),
				me.GemInterworkingTerminationPoint_InterworkingTerminationPointPointer:  uint16(0),
				me.GemInterworkingTerminationPoint_GalProfilePointer:                    uint16(1),
				me.GemInterworkingTerminationPoint_GalLoopbackConfiguration:             uint8(1),
			}, failedMask: 0x0100,
		},
		{
			name: "RFC 4115 meter", classID: me.TrafficDescriptorClassID, entityID: 3,
			attributes: me.AttributeValueMap{
				me.TrafficDescriptor_MeterType: uint8(1),
			}, failedMask: 0x0100,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := store.Create(test.classID, test.entityID, test.attributes)
			var result *mib.ResultError
			if !errors.As(err, &result) || result.Result != me.AttributeFailure ||
				result.FailedMask != test.failedMask {
				t.Fatalf("Create() error = %#v, want AttributeFailure/%#x", err, test.failedMask)
			}
		})
	}

	for _, test := range []struct {
		name       string
		key        mib.Key
		attributes me.AttributeValueMap
		failedMask uint16
	}{
		{
			name: "battery monitoring", key: mib.Key{ClassID: me.OnuGClassID, EntityID: 0},
			attributes: me.AttributeValueMap{me.OnuG_BatteryBackup: uint8(1)}, failedMask: 0x0400,
		},
		{
			name: "fixed GEM block", key: mib.Key{ClassID: me.AniGClassID, EntityID: aniEntityID},
			attributes: me.AttributeValueMap{me.AniG_GemBlockLength: uint16(64)}, failedMask: 0x2000,
		},
		{
			name: "mismatched Ethernet type",
			key:  mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: 0x0101},
			attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_ExpectedType: uint8(47),
			}, failedMask: 0x8000,
		},
		{
			name: "fixed maximum frame size",
			key:  mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: 0x0101},
			attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_MaxFrameSize: uint16(1518),
			}, failedMask: 0x0100,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := store.Set(test.key, test.attributes)
			var result *mib.ResultError
			if !errors.As(err, &result) || result.Result != me.AttributeFailure ||
				result.FailedMask != test.failedMask {
				t.Fatalf("Set() error = %#v, want AttributeFailure/%#x", err, test.failedMask)
			}
		})
	}
}

func TestXG2010GCapabilitiesCoverAdvertisedEnumerations(t *testing.T) {
	factory, err := XG2010G(Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := XG2010GSupportedAttributeMasks(pon.GPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := XG2010GAttributeCapabilities(pon.GPON)
	var missing []string
	for classID, mask := range masks {
		definitions, omciErr := me.GetAttributesDefinitions(classID)
		if omciErr.StatusCode() != me.Success {
			t.Fatal(omciErr.GetError())
		}
		for _, definition := range definitions {
			if definition.AttributeType != me.EnumerationAttributeType || definition.Mask&mask == 0 {
				continue
			}
			key := mib.AttributeCapabilityKey{ClassID: classID, Name: definition.GetName()}
			if capability, present := capabilities[key]; !present || len(capability.CodePoints) == 0 {
				missing = append(missing, classID.String()+"/"+definition.GetName())
			}
		}
	}
	if len(missing) != 0 {
		slices.Sort(missing)
		t.Fatalf("advertised enumerations without code points:\n%s", strings.Join(missing, "\n"))
	}
}

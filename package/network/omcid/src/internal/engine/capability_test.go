// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

func TestCapabilityMEsMatchXG2010GPolicy(t *testing.T) {
	protocol, store, classes := newCapabilityEngine(t)
	if got := len(store.Snapshot()); got >= 200 {
		t.Fatalf("persisted MIB entries = %d, capability declarations must remain synthesized", got)
	}

	omciInstance, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID: me.OmciClassID, EntityID: 0,
	}, 0xc000)
	if !handled || err != nil {
		t.Fatalf("get OMCI capability: handled=%t error=%v", handled, err)
	}
	classTable := omciInstance.Attributes[me.Omci_MeTypeTable].(me.TableRows)
	gotClasses := decodeCapabilityUint16Rows(t, classTable, 2)
	if !reflect.DeepEqual(gotClasses, classIDsAsUint16(classes)) {
		t.Fatalf("ME type table = %v, want %v", gotClasses, classes)
	}
	if containsUint16(gotClasses, uint16(me.IpHostConfigDataClassID)) {
		t.Fatalf("ME type table advertises unsupported IP host class %v", me.IpHostConfigDataClassID)
	}
	for _, required := range []me.ClassID{me.OmciClassID, me.ManagedEntityMeClassID, me.AttributeMeClassID} {
		if !containsUint16(gotClasses, uint16(required)) {
			t.Fatalf("ME type table omits capability class %v", required)
		}
	}
	messageTable := omciInstance.Attributes[me.Omci_MessageTypeTable].(me.TableRows)
	if messageTable.NumRows != len(capabilityMessageTypes) || len(messageTable.Rows) != len(capabilityMessageTypes) {
		t.Fatalf("message type table = %#v", messageTable)
	}

	tcontCapability, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID: me.ManagedEntityMeClassID, EntityID: uint16(me.TContClassID),
	}, 0xff00)
	if !handled || err != nil {
		t.Fatalf("get T-CONT ME capability: handled=%t error=%v", handled, err)
	}
	actions := tcontCapability.Attributes[me.ManagedEntityMe_Actions].(uint32)
	if actions&(uint32(1)<<uint(me.Get)) == 0 || actions&(uint32(1)<<uint(me.Set)) == 0 ||
		actions&(uint32(1)<<uint(me.Create)) != 0 || actions&(uint32(1)<<uint(me.Delete)) != 0 {
		t.Fatalf("T-CONT actions = %#08x, want Get/Set without Create/Delete", actions)
	}
	instances := tcontCapability.Attributes[me.ManagedEntityMe_InstancesTable].(me.TableRows)
	if got := decodeCapabilityUint16Rows(t, instances, 2); len(got) != 8 || got[0] != 0x8001 || got[7] != 0x8008 {
		t.Fatalf("T-CONT instances = %#v", got)
	}
	if support := tcontCapability.Attributes[me.ManagedEntityMe_Support]; support != uint8(me.PartiallySupported) {
		t.Fatalf("T-CONT support = %#v", support)
	}

	onu3Capability, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID: me.ManagedEntityMeClassID, EntityID: uint16(me.Onu3GClassID),
	}, 0x0c00)
	if !handled || err != nil {
		t.Fatalf("get ONU3-G ME capability: handled=%t error=%v", handled, err)
	}
	onu3Actions := onu3Capability.Attributes[me.ManagedEntityMe_Actions].(uint32)
	for _, action := range []me.MsgType{me.Get, me.GetNext, me.Set} {
		if onu3Actions&(uint32(1)<<uint(action)) == 0 {
			t.Fatalf("ONU3-G actions %#08x omit %v", onu3Actions, action)
		}
	}
	onu3AVCs := onu3Capability.Attributes[me.ManagedEntityMe_AvcsTable].(me.TableRows)
	if !reflect.DeepEqual(onu3AVCs.Rows, []byte{4, 5}) {
		t.Fatalf("ONU3-G AVC table = %#v", onu3AVCs)
	}
	aniCapability, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID: me.ManagedEntityMeClassID, EntityID: uint16(me.AniGClassID),
	}, 0x0c00)
	if !handled || err != nil {
		t.Fatalf("get ANI-G ME capability: handled=%t error=%v", handled, err)
	}
	aniAVCs := aniCapability.Attributes[me.ManagedEntityMe_AvcsTable].(me.TableRows)
	if !reflect.DeepEqual(aniAVCs.Rows, []byte{8, 10, 14}) {
		t.Fatalf("ANI-G AVC table = %#v", aniAVCs)
	}
	uniCapability, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID:  me.ManagedEntityMeClassID,
		EntityID: uint16(me.PhysicalPathTerminationPointEthernetUniClassID),
	}, 0x0c00)
	if !handled || err != nil {
		t.Fatalf("get Ethernet UNI ME capability: handled=%t error=%v", handled, err)
	}
	uniAVCs := uniCapability.Attributes[me.ManagedEntityMe_AvcsTable].(me.TableRows)
	if !reflect.DeepEqual(uniAVCs.Rows, []byte{6, 12}) {
		t.Fatalf("Ethernet UNI AVC table = %#v", uniAVCs)
	}

	onuDefinition, definitionErr := capabilityDefinition(me.OnuGClassID)
	if definitionErr != nil {
		t.Fatal(definitionErr)
	}
	logicalID, attributeErr := me.GetAttributeDefinitionByName(
		onuDefinition.AttributeDefinitions, me.OnuG_LogicalOnuId)
	if attributeErr != nil {
		t.Fatal(attributeErr)
	}
	_, err, handled = protocol.getCapabilityLocked(mib.Key{
		ClassID:  me.AttributeMeClassID,
		EntityID: capabilityAttributeID(me.OnuGClassID, logicalID.GetIndex()),
	}, 0xff80)
	var result *mib.ResultError
	if !handled || !errors.As(err, &result) || result.Result != me.UnknownInstance {
		t.Fatalf("unadvertised ONU-G attribute capability error = %#v", err)
	}

	definition, definitionErr := capabilityDefinition(me.TContClassID)
	if definitionErr != nil {
		t.Fatal(definitionErr)
	}
	allocID, attributeErr := me.GetAttributeDefinitionByName(definition.AttributeDefinitions, me.TCont_AllocId)
	if attributeErr != nil {
		t.Fatal(attributeErr)
	}
	attributeID := capabilityAttributeID(me.TContClassID, allocID.GetIndex())
	attributeCapability, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID: me.AttributeMeClassID, EntityID: attributeID,
	}, 0xff80)
	if !handled || err != nil {
		t.Fatalf("get Alloc-ID attribute capability: handled=%t error=%v", handled, err)
	}
	if got := string(attributeCapability.Attributes[me.AttributeMe_Name].([]byte)); got[:len(me.TCont_AllocId)] != me.TCont_AllocId {
		t.Fatalf("attribute name = %q", got)
	}
	if got := attributeCapability.Attributes[me.AttributeMe_Format]; got != uint8(4) {
		t.Fatalf("Alloc-ID format = %#v, want unsigned integer", got)
	}
}

func TestCapabilityInstanceTableTracksMIBAndUsesGetNext(t *testing.T) {
	protocol, store, _ := newCapabilityEngine(t)
	key := mib.Key{ClassID: me.ManagedEntityMeClassID, EntityID: uint16(me.GalEthernetProfileClassID)}

	get := func(tci uint16) *omci.GetResponse {
		request := encodeRequest(t, tci, omci.GetRequestType, &omci.GetRequest{
			MeBasePacket:  omci.MeBasePacket{EntityClass: key.ClassID, EntityInstance: key.EntityID},
			AttributeMask: 0x0200,
		})
		encoded, err := protocol.Handle(request)
		if err != nil {
			t.Fatalf("Handle(capability Get) error = %v", err)
		}
		return decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	}

	if before := get(1).Attributes[me.ManagedEntityMe_InstancesTable]; before != uint32(0) {
		t.Fatalf("initial GAL instance table length = %#v, want 0", before)
	}
	if err := store.Create(me.GalEthernetProfileClassID, 0x123, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatalf("Create(GAL) error = %v", err)
	}
	if after := get(2).Attributes[me.ManagedEntityMe_InstancesTable]; after != uint32(2) {
		t.Fatalf("updated GAL instance table length = %#v, want 2", after)
	}

	next := encodeRequest(t, 3, omci.GetNextRequestType, &omci.GetNextRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: key.ClassID, EntityInstance: key.EntityID},
		AttributeMask: 0x0200,
	})
	encoded, err := protocol.Handle(next)
	if err != nil {
		t.Fatalf("Handle(capability GetNext) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetNextResponse).(*omci.GetNextResponse)
	rows, ok := response.Attributes[me.ManagedEntityMe_InstancesTable].([]byte)
	if !ok || len(rows) < 2 || binary.BigEndian.Uint16(rows) != 0x123 {
		t.Fatalf("GAL GetNext rows = %x", rows)
	}
}

func TestCapabilityAttributeCodePointsUseGetNext(t *testing.T) {
	protocol, _, _ := newCapabilityEngine(t)
	definition, err := capabilityDefinition(me.MulticastOperationsProfileClassID)
	if err != nil {
		t.Fatal(err)
	}
	attribute, err := me.GetAttributeDefinitionByName(definition.AttributeDefinitions,
		me.MulticastOperationsProfile_IgmpVersion)
	if err != nil {
		t.Fatal(err)
	}
	key := mib.Key{ClassID: me.AttributeMeClassID,
		EntityID: capabilityAttributeID(me.MulticastOperationsProfileClassID, attribute.GetIndex())}

	request := encodeRequest(t, 1, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: key.ClassID, EntityInstance: key.EntityID},
		AttributeMask: 0x0100,
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(capability Get) error = %v", err)
	}
	get := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if get.Result != me.Success || get.Attributes[me.AttributeMe_CodePointsTable] != uint32(10) {
		t.Fatalf("code-point table Get response = %#v", get)
	}

	request = encodeRequest(t, 2, omci.GetNextRequestType, &omci.GetNextRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: key.ClassID, EntityInstance: key.EntityID},
		AttributeMask: 0x0100,
	})
	encoded, err = protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(capability Get Next) error = %v", err)
	}
	next := decodeResponse(t, encoded).Layer(omci.LayerTypeGetNextResponse).(*omci.GetNextResponse)
	rows, ok := next.Attributes[me.AttributeMe_CodePointsTable].([]byte)
	if !ok || len(rows) < 10 {
		t.Fatalf("code-point table Get Next rows = %#v", next.Attributes[me.AttributeMe_CodePointsTable])
	}
	got := make([]uint16, 5)
	for index := range got {
		got[index] = binary.BigEndian.Uint16(rows[index*2:])
	}
	if want := []uint16{1, 2, 3, 16, 17}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IGMP/MLD code points = %v, want %v", got, want)
	}
	for _, value := range rows[10:] {
		if value != 0 {
			t.Fatalf("code-point table baseline padding = %x", rows[10:])
		}
	}
}

func TestCapabilityMEsOmitUnsupportedOptionalAttributes(t *testing.T) {
	protocol, _, _ := newCapabilityEngine(t)
	for _, test := range []struct {
		classID me.ClassID
		name    string
	}{
		{me.GemInterworkingTerminationPointClassID, me.GemInterworkingTerminationPoint_PptpCounter},
		{me.GemInterworkingTerminationPointClassID, me.GemInterworkingTerminationPoint_OperationalState},
		{me.GemPortNetworkCtpClassID, me.GemPortNetworkCtp_UniCounter},
		{me.GemPortNetworkCtpClassID, me.GemPortNetworkCtp_EncryptionState},
		{me.GemPortNetworkCtpClassID, me.GemPortNetworkCtp_EncryptionKeyRing},
		{me.MacBridgePortConfigurationDataClassID, me.MacBridgePortConfigurationData_Deprecated1},
		{me.MacBridgePortConfigurationDataClassID, me.MacBridgePortConfigurationData_PortMacAddress},
		{me.MacBridgePortConfigurationDataClassID, me.MacBridgePortConfigurationData_LaspIdPointer},
		{me.TrafficDescriptorClassID, me.TrafficDescriptor_ColourMode},
		{me.TrafficDescriptorClassID, me.TrafficDescriptor_IngressColourMarking},
		{me.TrafficDescriptorClassID, me.TrafficDescriptor_EgressColourMarking},
		{me.MulticastOperationsProfileClassID, me.MulticastOperationsProfile_LostGroupsListTable},
		{me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID,
			me.GemPortNetworkCtpPerformanceMonitoringHistoryData_EncryptionKeyErrors},
	} {
		definition, err := capabilityDefinition(test.classID)
		if err != nil {
			t.Fatal(err)
		}
		attribute, err := me.GetAttributeDefinitionByName(definition.AttributeDefinitions, test.name)
		if err != nil {
			t.Fatal(err)
		}
		_, err, handled := protocol.getCapabilityLocked(mib.Key{
			ClassID:  me.AttributeMeClassID,
			EntityID: capabilityAttributeID(test.classID, attribute.GetIndex()),
		}, 0xff80)
		var result *mib.ResultError
		if !handled || !errors.As(err, &result) || result.Result != me.UnknownInstance {
			t.Errorf("attribute capability %v/%s error = %#v", test.classID, test.name, err)
		}
	}

	definition, err := capabilityDefinition(me.GemInterworkingTerminationPointClassID)
	if err != nil {
		t.Fatal(err)
	}
	loopback, err := me.GetAttributeDefinitionByName(definition.AttributeDefinitions,
		me.GemInterworkingTerminationPoint_GalLoopbackConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	_, err, handled := protocol.getCapabilityLocked(mib.Key{
		ClassID: me.AttributeMeClassID,
		EntityID: capabilityAttributeID(me.GemInterworkingTerminationPointClassID,
			loopback.GetIndex()),
	}, 0xff80)
	if !handled || err != nil {
		t.Fatalf("mandatory GAL loopback attribute capability: handled=%t error=%v", handled, err)
	}
}

func TestAttributeMEsExposeXG2010GValueConstraints(t *testing.T) {
	protocol, _, _ := newCapabilityEngine(t)
	get := func(classID me.ClassID, name string) mib.Instance {
		t.Helper()
		definition, err := capabilityDefinition(classID)
		if err != nil {
			t.Fatal(err)
		}
		attribute, err := me.GetAttributeDefinitionByName(definition.AttributeDefinitions, name)
		if err != nil {
			t.Fatal(err)
		}
		instance, err, handled := protocol.getCapabilityLocked(mib.Key{
			ClassID:  me.AttributeMeClassID,
			EntityID: capabilityAttributeID(classID, attribute.GetIndex()),
		}, 0xff80)
		if !handled || err != nil {
			t.Fatalf("get attribute capability %v/%s: handled=%t error=%v",
				classID, name, handled, err)
		}
		return instance
	}

	gal := get(me.GalEthernetProfileClassID, me.GalEthernetProfile_MaximumGemPayloadSize)
	if lower, upper := gal.Attributes[me.AttributeMe_LowerLimit], gal.Attributes[me.AttributeMe_UpperLimit]; lower != uint32(48) || upper != uint32(48) {
		t.Fatalf("GAL payload bounds = %#v..%#v, want 48..48", lower, upper)
	}

	loopback := get(me.GemInterworkingTerminationPointClassID,
		me.GemInterworkingTerminationPoint_GalLoopbackConfiguration)
	if got := decodeCapabilityUint16Rows(t,
		loopback.Attributes[me.AttributeMe_CodePointsTable].(me.TableRows), 2); !reflect.DeepEqual(got, []uint16{0}) {
		t.Fatalf("GAL loopback code points = %v, want [0]", got)
	}

	meter := get(me.TrafficDescriptorClassID, me.TrafficDescriptor_MeterType)
	if got := decodeCapabilityUint16Rows(t,
		meter.Attributes[me.AttributeMe_CodePointsTable].(me.TableRows), 2); !reflect.DeepEqual(got, []uint16{0, 2}) {
		t.Fatalf("traffic-descriptor meter code points = %v, want [0 2]", got)
	}
}

func TestKnownButUnsupportedClassReturnsUnknownEntity(t *testing.T) {
	protocol, _, _ := newCapabilityEngine(t)
	request := encodeRequest(t, 1, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.IpHostConfigDataClassID, EntityInstance: 1,
		},
		AttributeMask: 0x8000,
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(unsupported class) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.UnknownEntity {
		t.Fatalf("unsupported class result = %v, want UnknownEntity", response.Result)
	}
}

func TestCapabilityAndAttributePolicyUseProtocolErrorResponses(t *testing.T) {
	protocol, _, _ := newCapabilityEngine(t)
	request := encodeRequestForDevice(t, 1, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.OmciClassID, EntityInstance: 0, Extended: true,
		},
		AttributeMask: 0xc000,
	}, omci.ExtendedIdent)
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(extended OMCI capability Get) error = %v", err)
	}
	capability := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if capability.Result != me.Success ||
		capability.Attributes[me.Omci_MeTypeTable] != uint32(len(model.XG2010GSupportedClasses(pon.GPON))*2) ||
		capability.Attributes[me.Omci_MessageTypeTable] != uint32(len(capabilityMessageTypes)) {
		t.Fatalf("extended OMCI capability response = %#v", capability)
	}

	request = encodeRequest(t, 2, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.OnuGClassID, EntityInstance: 0},
		AttributeMask: 0x0040,
	})
	encoded, err = protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(unadvertised ONU-G attribute Get) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.AttributeFailure || response.UnsupportedAttributeMask != 0x0040 {
		t.Fatalf("unadvertised attribute result=%v unsupported=%#x",
			response.Result, response.UnsupportedAttributeMask)
	}
}

func TestCapabilityAttributeIDsAreUnique(t *testing.T) {
	seen := make(map[uint16]string)
	for _, classID := range model.XG2010GSupportedClasses(pon.GPON) {
		definition, err := capabilityDefinition(classID)
		if err != nil {
			t.Fatal(err)
		}
		for _, index := range me.GetAttributeDefinitionMapKeys(definition.AttributeDefinitions) {
			if index == 0 {
				continue
			}
			id := capabilityAttributeID(classID, index)
			name := definition.GetName() + "/" + definition.AttributeDefinitions[index].GetName()
			if previous, duplicate := seen[id]; duplicate {
				t.Fatalf("Attribute ME ID %#x is shared by %s and %s", id, previous, name)
			}
			seen[id] = name
			decodedClass, decodedIndex := decodeCapabilityAttributeID(id)
			if decodedClass != classID || decodedIndex != index {
				t.Fatalf("Attribute ME ID %#x decodes to %v/%d, want %v/%d",
					id, decodedClass, decodedIndex, classID, index)
			}
		}
	}
}

func newCapabilityEngine(t *testing.T) (*Engine, *mib.Store, []me.ClassID) {
	t.Helper()
	factory, err := model.XG2010G(model.Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatal(err)
	}
	classes := model.XG2010GSupportedClasses(pon.GPON)
	masks, err := model.XG2010GSupportedAttributeMasks(pon.GPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := mib.NewWithOptions(factory, mib.Options{
		SupportedClasses: classes, SupportedAttributeMasks: masks,
		ValidateInstance:      model.XG2010GInstanceValidator(pon.GPON),
		AttributeCapabilities: model.XG2010GAttributeCapabilities(pon.GPON),
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(store), store, classes
}

func decodeCapabilityUint16Rows(t *testing.T, table me.TableRows, rowSize int) []uint16 {
	t.Helper()
	if rowSize != 2 || table.NumRows*rowSize != len(table.Rows) {
		t.Fatalf("invalid uint16 capability table %#v", table)
	}
	result := make([]uint16, table.NumRows)
	for index := range result {
		result[index] = binary.BigEndian.Uint16(table.Rows[index*2:])
	}
	return result
}

func classIDsAsUint16(classes []me.ClassID) []uint16 {
	result := make([]uint16, len(classes))
	for index, classID := range classes {
		result[index] = uint16(classID)
	}
	return result
}

func containsUint16(values []uint16, wanted uint16) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

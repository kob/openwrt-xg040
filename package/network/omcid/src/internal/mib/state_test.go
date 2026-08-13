// SPDX-License-Identifier: Apache-2.0

package mib

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	me "github.com/opencord/omci-lib-go/v2/generated"
)

func TestStateRoundTripRestoresCommittedMIB(t *testing.T) {
	factory := stateTestFactory("ABCD")
	store, err := New(factory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	state, err := ExportState(store.Snapshot(), store.DataSync())
	if err != nil {
		t.Fatalf("ExportState() error = %v", err)
	}
	document, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal(state) error = %v", err)
	}
	var decoded State
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("Unmarshal(state) error = %v", err)
	}
	restored, err := NewFromState(factory, decoded, Options{})
	if err != nil {
		t.Fatalf("NewFromState() error = %v", err)
	}
	if restored.DataSync() != store.DataSync() ||
		!reflect.DeepEqual(restored.Snapshot(), store.Snapshot()) {
		t.Fatalf("restored MIB differs: sync=%d/%d\nrestored=%#v\nwant=%#v",
			restored.DataSync(), store.DataSync(), restored.Snapshot(), store.Snapshot())
	}
}

func TestStateCodecPreservesSupportedAttributeTypes(t *testing.T) {
	snapshot := []Instance{{
		Key:    Key{ClassID: me.OnuDataClassID},
		Origin: OriginONU,
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
			"u8":                   uint8(1),
			"u16":                  uint16(2),
			"u32":                  uint32(3),
			"u64":                  uint64(4),
			"bytes":                []byte{5, 6},
			"u16s":                 []uint16{7, 8},
			"u32s":                 []uint32{9, 10},
			"u64s":                 []uint64{11, 12},
			"table":                me.TableRows{NumRows: 1, Rows: []byte{13, 14}},
		},
	}}
	state, err := ExportState(snapshot, 0)
	if err != nil {
		t.Fatalf("ExportState() error = %v", err)
	}
	decoded, err := state.decode()
	if err != nil {
		t.Fatalf("decode() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, snapshot) {
		t.Fatalf("decoded state = %#v, want %#v", decoded, snapshot)
	}
}

func TestNewFromStateRejectsIdentityMismatch(t *testing.T) {
	store, err := New(stateTestFactory("ABCD"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	state, err := ExportState(store.Snapshot(), store.DataSync())
	if err != nil {
		t.Fatalf("ExportState() error = %v", err)
	}
	_, err = NewFromState(stateTestFactory("WXYZ"), state, Options{})
	if err == nil || !strings.Contains(err.Error(), "configured identity") {
		t.Fatalf("NewFromState(identity mismatch) error = %v", err)
	}
}

func TestNewFromStateRejectsDifferentCompatibilityDomain(t *testing.T) {
	factory := stateTestFactory("ABCD")
	store, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ExportState(store.Snapshot(), store.DataSync(), "xg2010g:gpon")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewFromState(factory, state, Options{StateDomain: "xg2010g:xgspon"})
	if err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("NewFromState(cross-mode) error = %v", err)
	}
}

func TestNewFromStateRejectsUnsupportedPersistedClass(t *testing.T) {
	factory := stateTestFactory("ABCD")
	store, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatal(err)
	}
	state, err := ExportState(store.Snapshot(), store.DataSync())
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewFromState(factory, state, Options{SupportedClasses: []me.ClassID{
		me.OnuDataClassID, me.OnuGClassID,
	}})
	if err == nil || !strings.Contains(err.Error(), "not supported by this ONU") {
		t.Fatalf("NewFromState(unsupported class) error = %v", err)
	}
}

func TestNewFromStateRejectsStaleFactoryAttributeSet(t *testing.T) {
	factory := stateTestFactory("ABCD")
	store, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ExportState(store.Snapshot(), store.DataSync())
	if err != nil {
		t.Fatal(err)
	}
	for index := range state.Instances {
		if state.Instances[index].ClassID == me.OnuGClassID {
			attributes := state.Instances[index].Attributes[:0]
			for _, attribute := range state.Instances[index].Attributes {
				if attribute.Name != me.OnuG_TrafficManagementOption {
					attributes = append(attributes, attribute)
				}
			}
			state.Instances[index].Attributes = attributes
			break
		}
	}
	_, err = NewFromState(factory, state, Options{SupportedClasses: []me.ClassID{
		me.OnuDataClassID, me.OnuGClassID,
	}})
	if err == nil || !strings.Contains(err.Error(), "attribute set does not match") {
		t.Fatalf("NewFromState(stale factory attributes) error = %v", err)
	}
}

func TestNewFromStateAddsONU3GToLegacyFactoryState(t *testing.T) {
	legacyFactory := stateTestFactory("ABCD")
	legacy, err := New(legacyFactory)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ExportState(legacy.Snapshot(), legacy.DataSync())
	if err != nil {
		t.Fatal(err)
	}
	upgradedFactory := append(append([]Instance(nil), legacyFactory...), onu3TestInstance())
	restored, err := NewFromState(upgradedFactory, state, Options{})
	if err != nil {
		t.Fatalf("NewFromState(legacy state) error = %v", err)
	}
	instance, err := restored.Get(Key{ClassID: me.Onu3GClassID}, 0x7dc0)
	if err != nil {
		t.Fatalf("Get(added ONU3-G) error = %v", err)
	}
	if instance.Attributes[me.Onu3G_EnhancedMode] != uint8(1) ||
		instance.Attributes[me.Onu3G_TotalNumberOfStatusSnapshots] != uint16(16) {
		t.Fatalf("added ONU3-G = %#v", instance.Attributes)
	}
}

func TestRestoreONU3FactoryMergesSnapshotsButKeepsCurrentRestartReason(t *testing.T) {
	factory := append(stateTestFactory("ABCD"), onu3TestInstance())
	store, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 25)
	record[0] = 1
	if err := store.UpdateByCommand(map[Key]me.AttributeValueMap{
		{ClassID: me.Onu3GClassID}: {
			me.Onu3G_NumberOfValidStatusSnapshots: uint16(1),
			me.Onu3G_NextStatusSnapshotIndex:      uint16(1),
			me.Onu3G_StatusSnapshotRecordTable: me.TableRows{
				NumRows: 1, Rows: append([]byte(nil), record...),
			},
			me.Onu3G_MostRecentStatusSnapshot: append([]byte(nil), record...),
		},
	}); err != nil {
		t.Fatal(err)
	}
	state, err := ExportState(store.Snapshot(), store.DataSync())
	if err != nil {
		t.Fatal(err)
	}
	currentFactory := append(stateTestFactory("ABCD"), onu3TestInstance())
	currentFactory[len(currentFactory)-1].Attributes[me.Onu3G_LatestRestartReason] = uint8(9)
	merged, err := RestoreONU3Factory(currentFactory, state)
	if err != nil {
		t.Fatalf("RestoreONU3Factory() error = %v", err)
	}
	mergedStore, err := New(merged)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := mergedStore.Get(Key{ClassID: me.Onu3GClassID}, 0x5d00)
	if err != nil {
		t.Fatal(err)
	}
	if instance.Attributes[me.Onu3G_LatestRestartReason] != uint8(9) ||
		instance.Attributes[me.Onu3G_NumberOfValidStatusSnapshots] != uint16(1) ||
		instance.Attributes[me.Onu3G_NextStatusSnapshotIndex] != uint16(1) ||
		!reflect.DeepEqual(instance.Attributes[me.Onu3G_MostRecentStatusSnapshot], record) {
		t.Fatalf("merged ONU3-G = %#v", instance.Attributes)
	}
}

func TestRestoreONU3FactoryRejectsDifferentONUIdentity(t *testing.T) {
	persisted, err := New(append(stateTestFactory("ABCD"), onu3TestInstance()))
	if err != nil {
		t.Fatal(err)
	}
	state, err := ExportState(persisted.Snapshot(), persisted.DataSync())
	if err != nil {
		t.Fatal(err)
	}
	_, err = RestoreONU3Factory(append(stateTestFactory("WXYZ"), onu3TestInstance()), state)
	if err == nil || !strings.Contains(err.Error(), "configured identity") {
		t.Fatalf("RestoreONU3Factory(identity mismatch) error = %v", err)
	}
}

func TestStateValidationRejectsStructuralCorruption(t *testing.T) {
	valid := State{Version: StateVersion, Instances: []StateInstance{{
		ClassID: me.OnuDataClassID, Origin: OriginONU,
		Attributes: []StateAttribute{{Name: me.OnuData_MibDataSync, Kind: "uint8"}},
	}}}
	tests := map[string]State{
		"version":   {Version: StateVersion + 1, Instances: valid.Instances},
		"empty":     {Version: StateVersion},
		"duplicate": {Version: StateVersion, Instances: append(valid.Instances, valid.Instances[0])},
		"origin": {Version: StateVersion, Instances: []StateInstance{{
			ClassID: me.OnuDataClassID, Origin: Origin(9), Attributes: valid.Instances[0].Attributes,
		}}},
		"attribute": {Version: StateVersion, Instances: []StateInstance{{
			ClassID: me.OnuDataClassID, Origin: OriginONU,
			Attributes: []StateAttribute{{Name: me.OnuData_MibDataSync, Kind: "uint8", Unsigned: 256}},
		}}},
	}
	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			if err := state.Validate(); err == nil {
				t.Fatalf("Validate(%s) unexpectedly succeeded", name)
			}
		})
	}
}

func stateTestFactory(vendor string) []Instance {
	serial := append([]byte(vendor), 1, 2, 3, 4)
	return []Instance{
		{
			Key: Key{ClassID: me.OnuDataClassID},
			Attributes: me.AttributeValueMap{
				me.OnuData_MibDataSync: uint8(0),
			},
		},
		{
			Key: Key{ClassID: me.OnuGClassID},
			Attributes: me.AttributeValueMap{
				me.OnuG_VendorId:                []byte(vendor),
				me.OnuG_SerialNumber:            serial,
				me.OnuG_TrafficManagementOption: uint8(0),
			},
		},
	}
}

func onu3TestInstance() Instance {
	return Instance{
		Key: Key{ClassID: me.Onu3GClassID},
		Attributes: me.AttributeValueMap{
			me.Onu3G_LatestRestartReason:          uint8(0),
			me.Onu3G_TotalNumberOfStatusSnapshots: uint16(16),
			me.Onu3G_NumberOfValidStatusSnapshots: uint16(0),
			me.Onu3G_NextStatusSnapshotIndex:      uint16(0),
			me.Onu3G_StatusSnapshotRecordTable:    me.TableRows{},
			me.Onu3G_SnapAction:                   uint8(0),
			me.Onu3G_MostRecentStatusSnapshot:     make([]byte, 25),
			me.Onu3G_ResetAction:                  uint8(0),
			me.Onu3G_EnhancedMode:                 uint8(1),
		},
	}
}

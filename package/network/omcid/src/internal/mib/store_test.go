// SPDX-License-Identifier: Apache-2.0

package mib

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	me "github.com/opencord/omci-lib-go/v2/generated"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New([]Instance{{
		Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store
}

func TestCreateSetDeleteAdvancesDataSync(t *testing.T) {
	store := newTestStore(t)
	key := Key{ClassID: me.GalEthernetProfileClassID, EntityID: 1}

	err := store.Create(key.ClassID, key.EntityID, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if got := store.DataSync(); got != 1 {
		t.Fatalf("DataSync() = %d, want 1", got)
	}

	err = store.Set(key, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(64),
	})
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	instance, err := store.Get(key, 0x8000)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := instance.Attributes[me.GalEthernetProfile_MaximumGemPayloadSize]; got != uint16(64) {
		t.Fatalf("MaximumGemPayloadSize = %#v, want 64", got)
	}

	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if got := store.DataSync(); got != 3 {
		t.Fatalf("DataSync() = %d, want 3", got)
	}
	_, err = store.Get(key, 0x8000)
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.UnknownInstance {
		t.Fatalf("Get(deleted) error = %v, want UnknownInstance", err)
	}
}

func TestSetMibDataSyncUsesRequestedValueThenIncrements(t *testing.T) {
	for _, test := range []struct {
		name      string
		requested uint8
		want      uint8
	}{
		{name: "normal", requested: 42, want: 43},
		{name: "wrap", requested: 255, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			if err := store.Set(Key{ClassID: me.OnuDataClassID, EntityID: 0},
				me.AttributeValueMap{me.OnuData_MibDataSync: test.requested}); err != nil {
				t.Fatalf("Set(MIB data sync) error = %v", err)
			}
			if got := store.DataSync(); got != test.want {
				t.Fatalf("DataSync() = %d, want %d", got, test.want)
			}
			instance, err := store.Get(Key{ClassID: me.OnuDataClassID, EntityID: 0}, 0x8000)
			if err != nil {
				t.Fatalf("Get(ONU data) error = %v", err)
			}
			if got := instance.Attributes[me.OnuData_MibDataSync]; got != test.want {
				t.Fatalf("MibDataSync = %#v, want %d", got, test.want)
			}
		})
	}
}

func TestSetWithoutAttributeChangeDoesNotAdvanceDataSyncOrApply(t *testing.T) {
	applyCalls := 0
	store, err := NewWithApplier([]Instance{{
		Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}}, ApplyFunc(func(Change) error {
		applyCalls++
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	key := Key{ClassID: me.GalEthernetProfileClassID, EntityID: 1}
	attributes := me.AttributeValueMap{me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48)}
	if err := store.Create(key.ClassID, key.EntityID, attributes); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Set(key, attributes); err != nil {
		t.Fatalf("Set(unchanged) error = %v", err)
	}
	if store.DataSync() != 1 || applyCalls != 1 {
		t.Fatalf("unchanged Set changed state: sync=%d apply calls=%d", store.DataSync(), applyCalls)
	}
}

func TestRejectedMibDataSyncSetRollsBackRequestedCounter(t *testing.T) {
	wantError := errors.New("platform rejected MIB sync")
	store, err := NewWithApplier([]Instance{{
		Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}}, ApplyFunc(func(change Change) error {
		if change.Operation != OperationSet || change.MIBDataSync != 8 ||
			change.After.Attributes[me.OnuData_MibDataSync] != uint8(8) ||
			change.Snapshot[0].Attributes[me.OnuData_MibDataSync] != uint8(8) {
			t.Fatalf("candidate change = %#v, want atomic MIB data sync 8", change)
		}
		return wantError
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}

	err = store.Set(Key{ClassID: me.OnuDataClassID, EntityID: 0},
		me.AttributeValueMap{me.OnuData_MibDataSync: uint8(7)})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.ProcessingError ||
		!errors.Is(err, wantError) {
		t.Fatalf("Set(MIB data sync) error = %#v, want wrapped ProcessingError", err)
	}
	if store.DataSync() != 0 {
		t.Fatalf("DataSync() = %d after rejected Set, want 0", store.DataSync())
	}
}

func TestResetRetainsOnlyONUCreatedInstances(t *testing.T) {
	store := newTestStore(t)
	err := store.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := store.Reset(); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	if got := store.DataSync(); got != 0 {
		t.Fatalf("DataSync() after reset = %d, want 0", got)
	}
	if got := len(store.Snapshot()); got != 1 {
		t.Fatalf("len(Snapshot()) = %d, want 1", got)
	}
}

func TestResetPreservesONU3GNonVolatileSnapshots(t *testing.T) {
	store, err := New([]Instance{
		{
			Key:        Key{ClassID: me.OnuDataClassID},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		onu3TestInstance(),
	})
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 25)
	record[0] = 1
	if err := store.UpdateByCommand(map[Key]me.AttributeValueMap{
		{ClassID: me.Onu3GClassID}: {
			me.Onu3G_LatestRestartReason:          uint8(1),
			me.Onu3G_NumberOfValidStatusSnapshots: uint16(1),
			me.Onu3G_NextStatusSnapshotIndex:      uint16(1),
			me.Onu3G_StatusSnapshotRecordTable: me.TableRows{
				NumRows: 1, Rows: append([]byte(nil), record...),
			},
			me.Onu3G_MostRecentStatusSnapshot: append([]byte(nil), record...),
		},
	}); err != nil {
		t.Fatalf("UpdateByCommand() error = %v", err)
	}
	if err := store.Reset(); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	instance, err := store.Get(Key{ClassID: me.Onu3GClassID}, 0x5d00)
	if err != nil {
		t.Fatalf("Get(ONU3-G) error = %v", err)
	}
	if store.DataSync() != 0 || instance.Attributes[me.Onu3G_LatestRestartReason] != uint8(1) ||
		instance.Attributes[me.Onu3G_NumberOfValidStatusSnapshots] != uint16(1) ||
		instance.Attributes[me.Onu3G_NextStatusSnapshotIndex] != uint16(1) ||
		!reflect.DeepEqual(instance.Attributes[me.Onu3G_MostRecentStatusSnapshot], record) {
		t.Fatalf("ONU3-G state after reset: sync=%d attributes=%#v", store.DataSync(), instance.Attributes)
	}
}

func TestPlatformApplyFailureDoesNotCommitCandidate(t *testing.T) {
	wantError := errors.New("platform rejected service graph")
	store, err := NewWithApplier([]Instance{{
		Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}}, ApplyFunc(func(change Change) error {
		if change.Operation != OperationCreate || change.MIBDataSync != 1 {
			t.Fatalf("change = %#v, want create/data-sync 1", change)
		}
		if len(change.Snapshot) != 2 {
			t.Fatalf("candidate snapshot has %d MEs, want 2", len(change.Snapshot))
		}
		return wantError
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}

	err = store.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.ProcessingError ||
		!errors.Is(err, wantError) {
		t.Fatalf("Create() error = %#v, want wrapped platform ProcessingError", err)
	}
	if got := store.DataSync(); got != 0 {
		t.Fatalf("DataSync() = %d after rejected apply, want 0", got)
	}
	if got := len(store.Snapshot()); got != 1 {
		t.Fatalf("len(Snapshot()) = %d after rejected apply, want 1", got)
	}
}

func TestSupportedClassPolicyRejectsKnownUnimplementedClass(t *testing.T) {
	store, err := NewWithOptions([]Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}, Options{SupportedClasses: []me.ClassID{me.OnuDataClassID, me.GalEthernetProfileClassID}})
	if err != nil {
		t.Fatalf("NewWithOptions() error = %v", err)
	}

	err = store.Create(me.IpHostConfigDataClassID, 1, me.AttributeValueMap{})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.UnknownEntity {
		t.Fatalf("Create(unsupported known class) error = %#v, want UnknownEntity", err)
	}
	if _, err = store.Get(Key{ClassID: me.IpHostConfigDataClassID, EntityID: 1}, 0x8000); !errors.As(err, &result) || result.Result != me.UnknownEntity {
		t.Fatalf("Get(unsupported known class) error = %#v, want UnknownEntity", err)
	}
	if err = store.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatalf("Create(supported class) error = %v", err)
	}
	if !store.SupportsClass(me.GalEthernetProfileClassID) || store.SupportsClass(me.IpHostConfigDataClassID) {
		t.Fatal("SupportsClass does not match configured policy")
	}
}

func TestExplicitAttributePolicyMustCoverExactlySupportedClasses(t *testing.T) {
	factory := []Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}
	classes := []me.ClassID{me.OnuDataClassID, me.GalEthernetProfileClassID}
	if _, err := NewWithOptions(factory, Options{
		SupportedClasses: classes,
		SupportedAttributeMasks: map[me.ClassID]uint16{
			me.OnuDataClassID: 0x8000,
		},
	}); err == nil || !strings.Contains(err.Error(), "has no attribute policy") {
		t.Fatalf("incomplete attribute policy error = %v", err)
	}
	if _, err := NewWithOptions(factory, Options{
		SupportedClasses: classes,
		SupportedAttributeMasks: map[me.ClassID]uint16{
			me.OnuDataClassID:            0x8000,
			me.GalEthernetProfileClassID: 0x8000,
			me.IpHostConfigDataClassID:   0x8000,
		},
	}); err == nil || !strings.Contains(err.Error(), "contains unsupported") {
		t.Fatalf("extra attribute policy error = %v", err)
	}
}

func TestAttributeCapabilitiesRequireAdvertisedAttributes(t *testing.T) {
	factory := []Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}
	options := Options{
		SupportedClasses: []me.ClassID{me.OnuDataClassID},
		SupportedAttributeMasks: map[me.ClassID]uint16{
			me.OnuDataClassID: 0x8000,
		},
		AttributeCapabilities: map[AttributeCapabilityKey]AttributeCapability{
			{ClassID: me.OnuDataClassID, Name: me.OnuData_MibDataSync}: {
				LowerLimit: 0, UpperLimit: 255,
			},
		},
	}
	store, err := NewWithOptions(factory, options)
	if err != nil {
		t.Fatalf("NewWithOptions() error = %v", err)
	}
	capability, present := store.AttributeCapability(me.OnuDataClassID, me.OnuData_MibDataSync)
	if !present || capability.UpperLimit != 255 {
		t.Fatalf("AttributeCapability() = %#v/%t", capability, present)
	}

	options.AttributeCapabilities = map[AttributeCapabilityKey]AttributeCapability{
		{ClassID: me.OnuDataClassID, Name: "Missing"}: {},
	}
	if _, err := NewWithOptions(factory, options); err == nil || !strings.Contains(err.Error(), "invalid attribute capability") {
		t.Fatalf("unknown attribute capability error = %v", err)
	}
	options.AttributeCapabilities = map[AttributeCapabilityKey]AttributeCapability{
		{ClassID: me.OnuDataClassID, Name: me.OnuData_MibDataSync}: {
			LowerLimit: 2, UpperLimit: 1,
		},
	}
	if _, err := NewWithOptions(factory, options); err == nil || !strings.Contains(err.Error(), "above upper limit") {
		t.Fatalf("invalid attribute bounds error = %v", err)
	}
}

func TestSupportedAttributePolicyRejectsUnadvertisedFactoryAttribute(t *testing.T) {
	store, err := NewWithOptions([]Instance{{
		Key: Key{ClassID: me.OnuGClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuG_VendorId:            []byte("TEST"),
			me.OnuG_AdministrativeState: uint8(0),
		},
	}}, Options{SupportedClasses: []me.ClassID{me.OnuGClassID}})
	if err != nil {
		t.Fatalf("NewWithOptions() error = %v", err)
	}

	mask, explicit := store.SupportedAttributeMask(me.OnuGClassID)
	if !explicit || mask != 0x8200 {
		t.Fatalf("ONU-G supported attribute mask = %#x/%t, want 0x8200/true", mask, explicit)
	}
	_, err = store.Get(Key{ClassID: me.OnuGClassID, EntityID: 0}, 0x0040)
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.UnsupportedMask != 0x0040 {
		t.Fatalf("Get(unadvertised Logical ONU ID) error = %#v", err)
	}
	err = store.Set(Key{ClassID: me.OnuGClassID, EntityID: 0}, me.AttributeValueMap{
		me.OnuG_CredentialsStatus: uint8(1),
	})
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.UnsupportedMask != 0x0010 {
		t.Fatalf("Set(unadvertised credentials status) error = %#v", err)
	}
	if _, err = store.Get(Key{ClassID: me.OnuGClassID, EntityID: 0}, 0x8200); err != nil {
		t.Fatalf("Get(advertised attributes) error = %v", err)
	}
}

func TestPlatformChangeDoesNotAliasCommittedStore(t *testing.T) {
	store, err := NewWithApplier([]Instance{{
		Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}}, ApplyFunc(func(change Change) error {
		change.After.Attributes[me.GalEthernetProfile_MaximumGemPayloadSize] = uint16(999)
		change.Snapshot[0].Attributes[me.OnuData_MibDataSync] = uint8(99)
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	key := Key{ClassID: me.GalEthernetProfileClassID, EntityID: 1}
	if err := store.Create(key.ClassID, key.EntityID, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	instance, err := store.Get(key, 0x8000)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := instance.Attributes[me.GalEthernetProfile_MaximumGemPayloadSize]; got != uint16(48) {
		t.Fatalf("MaximumGemPayloadSize = %#v, want 48", got)
	}
}

func TestRejectsWriteToReadOnlyAttribute(t *testing.T) {
	store, err := New([]Instance{{
		Key: Key{ClassID: me.Onu2GClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.Onu2G_TotalGemPortIdNumber: uint16(256),
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = store.Set(Key{ClassID: me.Onu2GClassID, EntityID: 0}, me.AttributeValueMap{
		me.Onu2G_TotalGemPortIdNumber: uint16(1),
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.FailedMask != 0x0080 {
		t.Fatalf("Set(read-only) error = %#v, want attribute failure mask 0x0080", err)
	}
}

func TestAutonomousUpdateDoesNotAdvanceDataSyncOrApplyPlatform(t *testing.T) {
	applyCalls := 0
	key := Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: 0x101}
	store, err := NewWithApplier([]Instance{
		{
			Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuData_MibDataSync: uint8(0),
			},
		},
		{
			Key: key,
			Attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_SensedType:       uint8(0x2f),
				me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(1),
			},
		},
	}, ApplyFunc(func(Change) error {
		applyCalls++
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}

	changed, err := store.UpdateAutonomous(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
	})
	if err != nil {
		t.Fatalf("UpdateAutonomous() error = %v", err)
	}
	if got := changed[me.PhysicalPathTerminationPointEthernetUni_OperationalState]; got != uint8(0) {
		t.Fatalf("changed operational state = %#v, want 0", got)
	}
	if store.DataSync() != 0 || applyCalls != 0 {
		t.Fatalf("autonomous update changed sync/applier: sync=%d calls=%d", store.DataSync(), applyCalls)
	}

	changed, err = store.UpdateAutonomous(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
	})
	if err != nil {
		t.Fatalf("UpdateAutonomous(duplicate) error = %v", err)
	}
	if len(changed) != 0 {
		t.Fatalf("duplicate autonomous update changed = %#v, want empty", changed)
	}
}

func TestAutonomousUpdateCannotOverrideMibDataSync(t *testing.T) {
	store := newTestStore(t)
	_, err := store.UpdateAutonomous(Key{ClassID: me.OnuDataClassID, EntityID: 0},
		me.AttributeValueMap{me.OnuData_MibDataSync: uint8(7)})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure {
		t.Fatalf("UpdateAutonomous(MIB data sync) error = %#v, want AttributeFailure", err)
	}
	if store.DataSync() != 0 {
		t.Fatalf("DataSync() = %d, want 0", store.DataSync())
	}
}

func TestAutonomousBatchValidationFailureIsAtomic(t *testing.T) {
	key := Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: 0x101}
	store, err := New([]Instance{
		{
			Key: key,
			Attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(1),
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = store.UpdateAutonomousBatch(map[Key]me.AttributeValueMap{
		key: {
			me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
		},
		{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: 0x102}: {
			me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
		},
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.UnknownInstance {
		t.Fatalf("UpdateAutonomousBatch() error = %#v, want UnknownInstance", err)
	}
	instance, getErr := store.Get(key, 0x0400)
	if getErr != nil {
		t.Fatalf("Get(UNI) error = %v", getErr)
	}
	if instance.Attributes[me.PhysicalPathTerminationPointEthernetUni_OperationalState] != uint8(1) {
		t.Fatalf("rejected autonomous batch changed state: %#v", instance.Attributes)
	}
}

func TestCommandUpdateChangesMultipleMEsAndAdvancesDataSyncOnce(t *testing.T) {
	applyCalls := 0
	var changes []Change
	store, err := NewWithApplier([]Instance{
		{
			Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuData_MibDataSync: uint8(0),
			},
		},
		{
			Key: Key{ClassID: me.SoftwareImageClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.SoftwareImage_IsActive: uint8(1),
			},
		},
		{
			Key: Key{ClassID: me.SoftwareImageClassID, EntityID: 1},
			Attributes: me.AttributeValueMap{
				me.SoftwareImage_IsActive: uint8(0),
			},
		},
	}, ApplyFunc(func(change Change) error {
		applyCalls++
		changes = append(changes, change)
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	updates := map[Key]me.AttributeValueMap{
		{ClassID: me.SoftwareImageClassID, EntityID: 0}: {me.SoftwareImage_IsActive: uint8(0)},
		{ClassID: me.SoftwareImageClassID, EntityID: 1}: {me.SoftwareImage_IsActive: uint8(1)},
	}
	if err := store.UpdateByCommand(updates); err != nil {
		t.Fatalf("UpdateByCommand() error = %v", err)
	}
	if store.DataSync() != 1 || applyCalls != 1 || len(changes) != 1 ||
		changes[0].Operation != OperationCommand {
		t.Fatalf("command update state: sync=%d changes=%+v, want one command commit",
			store.DataSync(), changes)
	}
	for entityID, want := range map[uint16]uint8{0: 0, 1: 1} {
		instance, err := store.Get(Key{ClassID: me.SoftwareImageClassID, EntityID: entityID}, 0x2000)
		if err != nil {
			t.Fatalf("Get(software image %#x) error = %v", entityID, err)
		}
		if got := instance.Attributes[me.SoftwareImage_IsActive]; got != want {
			t.Fatalf("software image %#x active = %#v, want %d", entityID, got, want)
		}
	}

	if err := store.UpdateByCommand(updates); err != nil {
		t.Fatalf("UpdateByCommand(unchanged) error = %v", err)
	}
	if store.DataSync() != 1 {
		t.Fatalf("unchanged command update advanced data sync to %d", store.DataSync())
	}
	if applyCalls != 1 {
		t.Fatalf("unchanged command update caused %d apply calls, want 1 total", applyCalls)
	}
}

type recordingCommandTransaction struct {
	commitErr error
	abortErr  error
	commits   int
	aborts    int
}

func (t *recordingCommandTransaction) Commit() error {
	t.commits++
	return t.commitErr
}

func (t *recordingCommandTransaction) Abort() error {
	t.aborts++
	return t.abortErr
}

func TestTransactionalCommandCommitFailureRestoresPersistedCandidate(t *testing.T) {
	var changes []Change
	store, err := NewWithApplier([]Instance{
		{
			Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		{
			Key:        Key{ClassID: me.SoftwareImageClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.SoftwareImage_IsActive: uint8(1)},
		},
	}, ApplyFunc(func(change Change) error {
		changes = append(changes, change)
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	transaction := &recordingCommandTransaction{commitErr: errors.New("slot commit failed")}
	err = store.UpdateByCommandTransactional(map[Key]me.AttributeValueMap{
		{ClassID: me.SoftwareImageClassID, EntityID: 0}: {
			me.SoftwareImage_IsActive: uint8(0),
		},
	}, transaction)
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.ProcessingError ||
		!strings.Contains(err.Error(), "slot commit failed") {
		t.Fatalf("UpdateByCommandTransactional() error = %#v", err)
	}
	if transaction.commits != 1 || transaction.aborts != 1 || len(changes) != 2 {
		t.Fatalf("transaction/apply calls = %d/%d/%d, want 1/1/2",
			transaction.commits, transaction.aborts, len(changes))
	}
	if changes[0].MIBDataSync != 1 || changes[1].MIBDataSync != 0 ||
		changes[0].Snapshot[0].Attributes[me.OnuData_MibDataSync] ==
			changes[1].Snapshot[0].Attributes[me.OnuData_MibDataSync] {
		t.Fatalf("candidate/rollback changes = %#v", changes)
	}
	instance, getErr := store.Get(Key{ClassID: me.SoftwareImageClassID, EntityID: 0}, 0x2000)
	if getErr != nil || store.DataSync() != 0 ||
		instance.Attributes[me.SoftwareImage_IsActive] != uint8(1) {
		t.Fatalf("failed transaction committed state: sync=%d image=%#v error=%v",
			store.DataSync(), instance, getErr)
	}
}

func TestTransactionalUnchangedCommandStillCommitsPlatformAction(t *testing.T) {
	store, err := New([]Instance{
		{
			Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		{
			Key:        Key{ClassID: me.SoftwareImageClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.SoftwareImage_IsActive: uint8(1)},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	transaction := &recordingCommandTransaction{}
	if err := store.UpdateByCommandTransactional(map[Key]me.AttributeValueMap{
		{ClassID: me.SoftwareImageClassID, EntityID: 0}: {
			me.SoftwareImage_IsActive: uint8(1),
		},
	}, transaction); err != nil {
		t.Fatalf("UpdateByCommandTransactional() error = %v", err)
	}
	if transaction.commits != 1 || transaction.aborts != 0 || store.DataSync() != 0 {
		t.Fatalf("unchanged transaction calls/sync = %d/%d/%d, want 1/0/0",
			transaction.commits, transaction.aborts, store.DataSync())
	}
}

func TestCommandUpdateValidationFailureIsAtomic(t *testing.T) {
	store, err := New([]Instance{
		{
			Key: Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuData_MibDataSync: uint8(0),
			},
		},
		{
			Key: Key{ClassID: me.SoftwareImageClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.SoftwareImage_IsActive: uint8(1),
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = store.UpdateByCommand(map[Key]me.AttributeValueMap{
		{ClassID: me.SoftwareImageClassID, EntityID: 0}: {me.SoftwareImage_IsActive: uint8(0)},
		{ClassID: me.SoftwareImageClassID, EntityID: 1}: {me.SoftwareImage_IsActive: uint8(1)},
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.UnknownInstance {
		t.Fatalf("UpdateByCommand() error = %#v, want UnknownInstance", err)
	}
	instance, getErr := store.Get(Key{ClassID: me.SoftwareImageClassID, EntityID: 0}, 0x2000)
	if getErr != nil {
		t.Fatalf("Get(software image) error = %v", getErr)
	}
	if store.DataSync() != 0 || instance.Attributes[me.SoftwareImage_IsActive] != uint8(1) {
		t.Fatalf("rejected command update changed state: sync=%d image=%#v", store.DataSync(), instance)
	}
}

func TestSnapshotDoesNotAliasStore(t *testing.T) {
	store := newTestStore(t)
	snapshot := store.Snapshot()
	snapshot[0].Attributes[me.OnuData_MibDataSync] = uint8(99)

	instance, err := store.Get(Key{ClassID: me.OnuDataClassID, EntityID: 0}, 0x8000)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := instance.Attributes[me.OnuData_MibDataSync]; got != uint8(0) {
		t.Fatalf("MibDataSync = %#v, want 0", got)
	}
}

func TestGetReturnsKnownAttributesWithUnsupportedMask(t *testing.T) {
	store := newTestStore(t)
	instance, err := store.Get(Key{ClassID: me.OnuDataClassID, EntityID: 0}, 0xc000)
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.UnsupportedMask != 0x4000 {
		t.Fatalf("Get() error = %#v, want unsupported mask 0x4000", err)
	}
	if got := instance.Attributes[me.OnuData_MibDataSync]; got != uint8(0) {
		t.Fatalf("MibDataSync = %#v, want 0", got)
	}
}

func TestUnknownClassReturnsUnknownEntity(t *testing.T) {
	store := newTestStore(t)
	_, err := store.Get(Key{ClassID: me.ClassID(0xfffe), EntityID: 1}, 0x8000)
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.UnknownEntity {
		t.Fatalf("Get(unknown class) error = %#v, want UnknownEntity", err)
	}
}

func TestANIGRejectsInvalidThresholdAndARCCombinations(t *testing.T) {
	tests := []struct {
		name       string
		attributes me.AttributeValueMap
	}{
		{name: "ARC value", attributes: me.AttributeValueMap{me.AniG_Arc: uint8(2)}},
		{name: "SF range", attributes: me.AttributeValueMap{me.AniG_SignalFailThreshold: uint8(2)}},
		{name: "SD not below SF BER", attributes: me.AttributeValueMap{me.AniG_SignalDegradeThreshold: uint8(5)}},
		{name: "receive ordering", attributes: me.AttributeValueMap{me.AniG_UpperOpticalThreshold: uint8(50)}},
		{name: "transmit ordering", attributes: me.AttributeValueMap{me.AniG_LowerTransmitPowerThreshold: uint8(20)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newANIGStore(t)
			err := store.Set(Key{ClassID: me.AniGClassID, EntityID: 0x8001}, test.attributes)
			var result *ResultError
			if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.FailedMask == 0 {
				t.Fatalf("Set(%s) error = %#v, want masked AttributeFailure", test.name, err)
			}
			if store.DataSync() != 0 {
				t.Fatalf("Set(%s) data sync = %d, want 0", test.name, store.DataSync())
			}
		})
	}
}

func TestONURejectsInvalidAdministrativeState(t *testing.T) {
	store, err := New([]Instance{
		{
			Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		{
			Key: Key{ClassID: me.OnuGClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuG_VendorId:            []byte("TEST"),
				me.OnuG_Version:             make([]byte, 14),
				me.OnuG_SerialNumber:        make([]byte, 8),
				me.OnuG_AdministrativeState: uint8(0),
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = store.Set(Key{ClassID: me.OnuGClassID, EntityID: 0}, me.AttributeValueMap{
		me.OnuG_AdministrativeState: uint8(2),
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.FailedMask != 0x0200 {
		t.Fatalf("Set(invalid administrative state) error = %#v, want masked AttributeFailure", err)
	}
	if store.DataSync() != 0 {
		t.Fatalf("invalid Set data sync = %d, want 0", store.DataSync())
	}
}

func newANIGStore(t *testing.T) *Store {
	t.Helper()
	store, err := New([]Instance{
		{
			Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		{
			Key: Key{ClassID: me.AniGClassID, EntityID: 0x8001},
			Attributes: me.AttributeValueMap{
				me.AniG_SignalFailThreshold:         uint8(5),
				me.AniG_SignalDegradeThreshold:      uint8(9),
				me.AniG_Arc:                         uint8(0),
				me.AniG_ArcInterval:                 uint8(0),
				me.AniG_LowerOpticalThreshold:       uint8(40),
				me.AniG_UpperOpticalThreshold:       uint8(0),
				me.AniG_LowerTransmitPowerThreshold: uint8(0xec),
				me.AniG_UpperTransmitPowerThreshold: uint8(10),
			},
		},
	})
	if err != nil {
		t.Fatalf("New(ANI-G) error = %v", err)
	}
	return store
}

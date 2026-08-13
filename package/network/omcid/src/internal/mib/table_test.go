// SPDX-License-Identifier: Apache-2.0

package mib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	me "github.com/opencord/omci-lib-go/v2/generated"
)

const extendedVLANEntityID = 0x101

func TestExtendedVLANCreateInitializesCapacityAndDefaults(t *testing.T) {
	store := newExtendedVLANStore(t, Options{ExtendedVLANTableSize: 96})
	instance := snapshotInstance(t, store, Key{
		ClassID:  me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		EntityID: extendedVLANEntityID,
	})
	if got := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize]; got != uint16(96) {
		t.Fatalf("table maximum = %#v, want 96", got)
	}
	if got := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_InputTpid]; got != uint16(0x88a8) {
		t.Fatalf("input TPID = %#v, want 0x88a8", got)
	}
	if got := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_OutputTpid]; got != uint16(0x88a8) {
		t.Fatalf("output TPID = %#v, want 0x88a8", got)
	}
	if got := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_DownstreamMode]; got != uint8(0) {
		t.Fatalf("downstream mode = %#v, want 0", got)
	}
	if got := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_EnhancedMode]; got != uint8(1) {
		t.Fatalf("enhanced mode = %#v, want requested value 1", got)
	}
	want := me.TableRows{NumRows: 3, Rows: extendedVLANDefaultRows}
	if got := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable]; !tableRowsEqual(got, want) {
		t.Fatalf("default rows = %#v, want %#v", got, want)
	}
	rows := want.Rows
	if binary.BigEndian.Uint32(rows[0:4]) != 15<<28|4096<<15 ||
		binary.BigEndian.Uint32(rows[4:8]) != 15<<28|4096<<15 ||
		binary.BigEndian.Uint32(rows[16:20]) != 15<<28|4096<<15 ||
		binary.BigEndian.Uint32(rows[20:24]) != 14<<28|4096<<15 ||
		binary.BigEndian.Uint32(rows[32:36]) != 14<<28|4096<<15 ||
		binary.BigEndian.Uint32(rows[36:40]) != 14<<28|4096<<15 {
		t.Fatalf("default filter words are incorrectly encoded: %x", rows)
	}
}

func TestExtendedVLANCreateRejectsOLTWriteToReadOnlyDefault(t *testing.T) {
	store, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = store.Create(me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		extendedVLANEntityID, me.AttributeValueMap{
			me.ExtendedVlanTaggingOperationConfigurationData_AssociationType:                               uint8(2),
			me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer:                           uint16(0x101),
			me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize: uint16(1),
		})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.AttributeFailure || result.FailedMask != 0x4000 {
		t.Fatalf("Create(read-only table size) error = %#v, want attribute failure mask 0x4000", err)
	}
	if store.Exists(Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		EntityID: extendedVLANEntityID}) {
		t.Fatal("rejected Create committed an instance")
	}
}

func TestSetTableExtendedVLANAddsReplacesDeletesAndSorts(t *testing.T) {
	store := newExtendedVLANStore(t, Options{})
	key := Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: extendedVLANEntityID}
	row20 := classicVLANRow(0x20, 1)
	row10 := classicVLANRow(0x10, 2)
	setTable(t, store, key, 0x0400, me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable,
		append(append([]byte(nil), row20...), row10...))

	rows := getTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable)
	if rows.NumRows != 5 || !bytes.Equal(rows.Rows[:extendedVLANRowSize], row10) ||
		!bytes.Equal(rows.Rows[extendedVLANRowSize:2*extendedVLANRowSize], row20) {
		t.Fatalf("rows after insert = %x", rows.Rows)
	}

	replacement := classicVLANRow(0x10, 9)
	setTable(t, store, key, 0x0400, me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable, replacement)
	rows = getTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable)
	if rows.NumRows != 5 || !bytes.Equal(rows.Rows[:extendedVLANRowSize], replacement) {
		t.Fatalf("rows after replacement = %x", rows.Rows)
	}

	deletion := append([]byte(nil), replacement...)
	for index := 8; index < len(deletion); index++ {
		deletion[index] = 0xff
	}
	setTable(t, store, key, 0x0400, me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable, deletion)
	rows = getTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable)
	if rows.NumRows != 4 || bytes.Equal(rows.Rows[:extendedVLANRowSize], replacement) {
		t.Fatalf("rows after deletion = %x", rows.Rows)
	}
}

func TestSetTableWithoutTableChangeDoesNotAdvanceDataSyncOrApply(t *testing.T) {
	applyCalls := 0
	store := newExtendedVLANStore(t, Options{Applier: ApplyFunc(func(Change) error {
		applyCalls++
		return nil
	})})
	key := Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: extendedVLANEntityID}
	row := classicVLANRow(0x20, 1)
	setTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable, row)
	if store.DataSync() != 2 || applyCalls != 2 {
		t.Fatalf("first SetTable state: sync=%d apply calls=%d, want 2/2", store.DataSync(), applyCalls)
	}

	setTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable, row)
	if store.DataSync() != 2 || applyCalls != 2 {
		t.Fatalf("unchanged SetTable changed state: sync=%d apply calls=%d", store.DataSync(), applyCalls)
	}
}

func TestSetTableExtendedVLANCapacityFailureIsAtomic(t *testing.T) {
	applyCalls := 0
	store := newExtendedVLANStore(t, Options{
		ExtendedVLANTableSize: 4,
		Applier: ApplyFunc(func(change Change) error {
			applyCalls++
			return nil
		}),
	})
	key := Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: extendedVLANEntityID}
	updates := append(classicVLANRow(1, 1), classicVLANRow(2, 2)...)
	err := store.SetTable(key, 0x0400, me.AttributeValueMap{
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable: me.TableRows{
			NumRows: 2,
			Rows:    updates,
		},
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.ProcessingError {
		t.Fatalf("SetTable() error = %#v, want ProcessingError", err)
	}
	if store.DataSync() != 1 || applyCalls != 1 {
		t.Fatalf("failed SetTable changed state: sync=%d apply calls=%d", store.DataSync(), applyCalls)
	}
	rows := getTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable)
	if rows.NumRows != 3 || !bytes.Equal(rows.Rows, extendedVLANDefaultRows) {
		t.Fatalf("failed SetTable committed rows = %x", rows.Rows)
	}
}

func TestSetTablePlatformFailureRollsBackTableAndDataSync(t *testing.T) {
	wantError := errors.New("hardware rejected table")
	store := newExtendedVLANStore(t, Options{Applier: ApplyFunc(func(change Change) error {
		if change.Operation == OperationSetTable {
			if change.After == nil {
				t.Fatal("SetTable change has no candidate instance")
			}
			return wantError
		}
		return nil
	})})
	key := Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: extendedVLANEntityID}
	err := store.SetTable(key, 0x0400, me.AttributeValueMap{
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable: me.TableRows{
			NumRows: 1,
			Rows:    classicVLANRow(1, 1),
		},
	})
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.ProcessingError || !errors.Is(err, wantError) {
		t.Fatalf("SetTable() error = %#v, want wrapped platform ProcessingError", err)
	}
	if store.DataSync() != 1 {
		t.Fatalf("DataSync() = %d after rejected SetTable, want 1", store.DataSync())
	}
	rows := getTable(t, store, key, 0x0400,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable)
	if rows.NumRows != 3 || !bytes.Equal(rows.Rows, extendedVLANDefaultRows) {
		t.Fatalf("rejected SetTable committed rows = %x", rows.Rows)
	}
}

func TestSetTableEnhancedVLANControlAndOrdering(t *testing.T) {
	store := newExtendedVLANStore(t, Options{})
	key := Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: extendedVLANEntityID}
	row20 := enhancedVLANRow(1, 2, 0x20, 2)
	row10 := enhancedVLANRow(1, 0, 0x10, 1)
	setTable(t, store, key, 0x0040,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable,
		append(append([]byte(nil), row20...), row10...))
	rows := getTable(t, store, key, 0x0040,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable)
	if rows.NumRows != 2 || binary.BigEndian.Uint16(rows.Rows[2:4]) != 0x10 ||
		binary.BigEndian.Uint16(rows.Rows[enhancedExtendedVLANRowSize+2:enhancedExtendedVLANRowSize+4]) != 0x20 ||
		rows.Rows[0]>>6 != 0 || rows.Rows[enhancedExtendedVLANRowSize]>>6 != 0 {
		t.Fatalf("stored enhanced rows = %x", rows.Rows)
	}

	setTable(t, store, key, 0x0040,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable,
		enhancedVLANRow(2, 0, 0x10, 0))
	rows = getTable(t, store, key, 0x0040,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable)
	if rows.NumRows != 1 || binary.BigEndian.Uint16(rows.Rows[2:4]) != 0x20 {
		t.Fatalf("enhanced rows after deletion = %x", rows.Rows)
	}

	setTable(t, store, key, 0x0040,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable,
		enhancedVLANRow(3, 0, 0, 0))
	rows = getTable(t, store, key, 0x0040,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable)
	if rows.NumRows != 0 || len(rows.Rows) != 0 {
		t.Fatalf("enhanced rows after clear = %x", rows.Rows)
	}
}

func TestSetTableEnhancedVLANRejectsReservedControlAndDirection(t *testing.T) {
	tests := []struct {
		name string
		row  []byte
	}{
		{name: "control", row: enhancedVLANRow(0, 0, 1, 0)},
		{name: "direction", row: enhancedVLANRow(1, 3, 1, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newExtendedVLANStore(t, Options{})
			key := Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: extendedVLANEntityID}
			err := store.SetTable(key, 0x0040, me.AttributeValueMap{
				me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable: me.TableRows{
					NumRows: 1,
					Rows:    test.row,
				},
			})
			var result *ResultError
			if !errors.As(err, &result) || result.Result != me.ParameterError {
				t.Fatalf("SetTable() error = %#v, want ParameterError", err)
			}
			if store.DataSync() != 1 {
				t.Fatalf("DataSync() = %d after rejected SetTable, want 1", store.DataSync())
			}
		})
	}
}

func TestMulticastGEMCreateInitializesAddressTables(t *testing.T) {
	store, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	const entityID = 0x300
	if err := store.Create(me.MulticastGemInterworkingTerminationPointClassID, entityID,
		me.AttributeValueMap{
			me.MulticastGemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: uint16(0x400),
			me.MulticastGemInterworkingTerminationPoint_InterworkingOption:                   uint8(1),
			me.MulticastGemInterworkingTerminationPoint_ServiceProfilePointer:                uint16(0x100),
			me.MulticastGemInterworkingTerminationPoint_NotUsed1:                             uint16(0),
			me.MulticastGemInterworkingTerminationPoint_GalProfilePointer:                    uint16(0),
			me.MulticastGemInterworkingTerminationPoint_NotUsed2:                             uint8(0),
		}); err != nil {
		t.Fatalf("Create(multicast GEM IW) error = %v", err)
	}
	instance := snapshotInstance(t, store, Key{
		ClassID: me.MulticastGemInterworkingTerminationPointClassID, EntityID: entityID})
	for _, name := range []string{
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable,
		me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable,
	} {
		if got := instance.Attributes[name]; !tableRowsEqual(got, me.TableRows{}) {
			t.Fatalf("%s = %#v, want empty TableRows", name, got)
		}
	}
}

func TestSetTableMulticastAddressesReplaceDeleteAndSort(t *testing.T) {
	store := newMulticastTableStore(t)
	key := Key{ClassID: me.MulticastGemInterworkingTerminationPointClassID, EntityID: 0x300}

	row20 := multicastIPv4Row(200, 0x20, 0xe1000000, 0xe10000ff)
	row10 := multicastIPv4Row(200, 0x10, 0xe2000000, 0xe20000ff)
	setTable(t, store, key, 0x0080,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable,
		append(append([]byte(nil), row20...), row10...))
	rows := getTable(t, store, key, 0x0080,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable)
	if rows.NumRows != 2 || !bytes.Equal(rows.Rows[:multicastIPv4RowSize], row10) {
		t.Fatalf("stored IPv4 multicast rows = %x", rows.Rows)
	}

	replacement := multicastIPv4Row(200, 0x10, 0xef000000, 0xefffffff)
	setTable(t, store, key, 0x0080,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable, replacement)
	rows = getTable(t, store, key, 0x0080,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable)
	if rows.NumRows != 2 || !bytes.Equal(rows.Rows[:multicastIPv4RowSize], replacement) {
		t.Fatalf("replaced IPv4 multicast rows = %x", rows.Rows)
	}

	deletion := append([]byte(nil), replacement...)
	clear(deletion[4:])
	setTable(t, store, key, 0x0080,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable, deletion)
	rows = getTable(t, store, key, 0x0080,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable)
	if rows.NumRows != 1 || !bytes.Equal(rows.Rows, row20) {
		t.Fatalf("IPv4 multicast rows after delete = %x", rows.Rows)
	}

	ipv6 := multicastIPv6Row(201, 1, 0x100, 0x1ff)
	setTable(t, store, key, 0x0040,
		me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable, ipv6)
	rows = getTable(t, store, key, 0x0040,
		me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable)
	if rows.NumRows != 1 || !bytes.Equal(rows.Rows, ipv6) {
		t.Fatalf("stored IPv6 multicast rows = %x", rows.Rows)
	}
}

func TestSetTableMulticastAddressesRejectInvalidRowsAtomically(t *testing.T) {
	tests := []struct {
		name string
		mask uint16
		attr string
		row  []byte
	}{
		{name: "GEM", mask: 0x0080,
			attr: me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable,
			row:  multicastIPv4Row(4096, 1, 0xe0000000, 0xefffffff)},
		{name: "IPv4 unicast", mask: 0x0080,
			attr: me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable,
			row:  multicastIPv4Row(200, 1, 0x0a000001, 0x0a000002)},
		{name: "IPv4 reversed", mask: 0x0080,
			attr: me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable,
			row:  multicastIPv4Row(200, 1, 0xe1000002, 0xe1000001)},
		{name: "IPv6 unicast", mask: 0x0040,
			attr: me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable,
			row: func() []byte {
				row := multicastIPv6Row(200, 1, 1, 2)
				row[12] = 0x20
				return row
			}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newMulticastTableStore(t)
			err := store.SetTable(Key{ClassID: me.MulticastGemInterworkingTerminationPointClassID,
				EntityID: 0x300}, test.mask, me.AttributeValueMap{test.attr: me.TableRows{
				NumRows: 1, Rows: test.row,
			}})
			var result *ResultError
			if !errors.As(err, &result) || result.Result != me.ParameterError {
				t.Fatalf("SetTable() error = %#v, want ParameterError", err)
			}
			if store.DataSync() != 1 {
				t.Fatalf("DataSync() = %d after rejected row, want 1", store.DataSync())
			}
		})
	}
}

func TestSetTableMulticastACLPartsReplaceDeleteClearAndSort(t *testing.T) {
	store := newMulticastOperationsStore(t)
	key := Key{ClassID: me.MulticastOperationsProfileClassID, EntityID: 0x700}
	part0Key20 := multicastACLPart0(1, 0x20, 201, 100, 0x100, 0x1ff)
	part1Key20 := multicastACLPart1(1, 0x20, 2)
	part2Key20 := multicastACLPart2(1, 0x20, []byte{
		0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	})
	// The test bit is accepted for capability probing but always reads back zero
	// because this ONU supports all three ACL row parts.
	control := binary.BigEndian.Uint16(part2Key20[:2]) | tableTestMask
	binary.BigEndian.PutUint16(part2Key20[:2], control)
	part0Key10 := multicastACLPart0(1, 0x10, 200, 100, 0xe1000000, 0xe10000ff)
	setTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable,
		append(append(append(append([]byte(nil), part2Key20...), part1Key20...), part0Key20...), part0Key10...))

	rows := getTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable)
	if rows.NumRows != 4 {
		t.Fatalf("multicast ACL row count = %d, want 4", rows.NumRows)
	}
	wantControls := []uint16{0x0010, 0x0020, 0x0820, 0x1020}
	for index, want := range wantControls {
		if got := binary.BigEndian.Uint16(rows.Rows[index*multicastACLRowSize:]); got != want {
			t.Fatalf("multicast ACL control[%d] = %#x, want %#x; rows=%x", index, got, want, rows.Rows)
		}
	}

	reset := multicastACLPart1(1, 0x20, 255)
	binary.BigEndian.PutUint16(reset[14:16], 90)
	setTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable, reset)
	rows = getTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable)
	storedPart1 := rows.Rows[2*multicastACLRowSize : 3*multicastACLRowSize]
	if binary.BigEndian.Uint16(storedPart1[14:16]) != 90 ||
		binary.BigEndian.Uint16(storedPart1[20:22]) != 2 {
		t.Fatalf("preview reset action was persisted instead of preserving policy: %x", storedPart1)
	}

	setTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable,
		multicastACLControlRow(2, 2, 0x20))
	rows = getTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable)
	if rows.NumRows != 1 || binary.BigEndian.Uint16(rows.Rows[:2]) != 0x10 {
		t.Fatalf("multicast ACL delete did not remove all row parts: %x", rows.Rows)
	}

	setTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable,
		multicastACLControlRow(3, 0, 0))
	rows = getTable(t, store, key, 0x0200,
		me.MulticastOperationsProfile_DynamicAccessControlListTable)
	if rows.NumRows != 0 || len(rows.Rows) != 0 {
		t.Fatalf("multicast ACL clear left rows: %x", rows.Rows)
	}
}

func TestSetTableMulticastACLStaticTableUsesSameControlFormat(t *testing.T) {
	store := newMulticastOperationsStore(t)
	key := Key{ClassID: me.MulticastOperationsProfileClassID, EntityID: 0x700}
	part0 := multicastACLPart0(1, 7, 200, 0xffff, 0xe8000000, 0xe80000ff)
	part1 := multicastACLPart1(1, 7, 25)
	setTable(t, store, key, 0x0100,
		me.MulticastOperationsProfile_StaticAccessControlListTable,
		append(part0, part1...))
	rows := getTable(t, store, key, 0x0100,
		me.MulticastOperationsProfile_StaticAccessControlListTable)
	if rows.NumRows != 2 || binary.BigEndian.Uint16(rows.Rows[:2]) != 7 ||
		binary.BigEndian.Uint16(rows.Rows[multicastACLRowSize:]) != 0x0807 {
		t.Fatalf("stored static multicast ACL rows = %x", rows.Rows)
	}
}

func TestSetTableMulticastACLRejectsInvalidRowsAtomically(t *testing.T) {
	validPart0 := func() []byte {
		return multicastACLPart0(1, 1, 200, 100, 0xe1000000, 0xe10000ff)
	}
	tests := []struct {
		name string
		rows []byte
	}{
		{name: "reserved set control", rows: multicastACLPart0(0, 1, 200, 100, 0xe1000000, 0xe10000ff)},
		{name: "reserved row part", rows: multicastACLControlRow(1, 3, 1)},
		{name: "GEM Port-ID", rows: multicastACLPart0(1, 1, 4096, 100, 0xe1000000, 0xe10000ff)},
		{name: "reserved VLAN", rows: multicastACLPart0(1, 1, 200, 4096, 0xe1000000, 0xe10000ff)},
		{name: "IPv4 unicast", rows: multicastACLPart0(1, 1, 200, 100, 0x0a000001, 0x0a000002)},
		{name: "IPv4 reversed", rows: multicastACLPart0(1, 1, 200, 100, 0xe1000002, 0xe1000001)},
		{name: "part 0 reserved", rows: func() []byte {
			row := validPart0()
			row[23] = 1
			return row
		}()},
		{name: "preview reset", rows: multicastACLPart1(1, 1, 25)},
		{name: "part 1 reserved", rows: func() []byte {
			row := multicastACLPart1(1, 1, 2)
			row[22] = 1
			return row
		}()},
		{name: "IPv6 unicast", rows: func() []byte {
			part2 := multicastACLPart2(1, 1, []byte{0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0})
			return append(validPart0(), part2...)
		}()},
		{name: "part 2 reserved", rows: func() []byte {
			row := multicastACLPart2(1, 1, []byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
			row[14] = 1
			return row
		}()},
		{name: "overlap", rows: append(
			multicastACLPart0(1, 1, 200, 100, 0xe1000000, 0xe10000ff),
			multicastACLPart0(1, 2, 201, 200, 0xe1000080, 0xe10001ff)...),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newMulticastOperationsStore(t)
			err := store.SetTable(Key{ClassID: me.MulticastOperationsProfileClassID, EntityID: 0x700},
				0x0200, me.AttributeValueMap{
					me.MulticastOperationsProfile_DynamicAccessControlListTable: me.TableRows{
						NumRows: len(test.rows) / multicastACLRowSize,
						Rows:    test.rows,
					},
				})
			var result *ResultError
			if !errors.As(err, &result) || result.Result != me.ParameterError {
				t.Fatalf("SetTable() error = %#v, want ParameterError", err)
			}
			if store.DataSync() != 1 {
				t.Fatalf("DataSync() = %d after rejected ACL, want 1", store.DataSync())
			}
			rows := getTable(t, store,
				Key{ClassID: me.MulticastOperationsProfileClassID, EntityID: 0x700},
				0x0200, me.MulticastOperationsProfile_DynamicAccessControlListTable)
			if rows.NumRows != 0 || len(rows.Rows) != 0 {
				t.Fatalf("rejected ACL committed rows: %x", rows.Rows)
			}
		})
	}
}

func TestSetTableMulticastServicePackageControlAndValidation(t *testing.T) {
	store := newMulticastSubscriberStore(t)
	key := Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500}
	row20 := multicastServiceRow(1, 20, 100, 32, 20_000_000, 0x702)
	row10 := multicastServiceRow(1, 10, 4096, 16, 10_000_000, 0x701)
	setTable(t, store, key, 0x0400,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable,
		append(row20, row10...))
	rows := getTable(t, store, key, 0x0400,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable)
	if rows.NumRows != 2 || binary.BigEndian.Uint16(rows.Rows[:2]) != 10 ||
		binary.BigEndian.Uint16(rows.Rows[multicastServiceRowSize:]) != 20 {
		t.Fatalf("stored multicast service rows = %x", rows.Rows)
	}

	setTable(t, store, key, 0x0400,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable,
		multicastServiceControlRow(2, 10))
	rows = getTable(t, store, key, 0x0400,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable)
	if rows.NumRows != 1 || binary.BigEndian.Uint16(rows.Rows[:2]) != 20 {
		t.Fatalf("multicast service delete left rows = %x", rows.Rows)
	}

	setTable(t, store, key, 0x0400,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable,
		multicastServiceControlRow(3, 0))
	rows = getTable(t, store, key, 0x0400,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable)
	if rows.NumRows != 0 {
		t.Fatalf("multicast service clear left rows = %x", rows.Rows)
	}
}

func TestSetTableAllowedPreviewNormalizesTimeLeftAndDeletesParts(t *testing.T) {
	store := newMulticastSubscriberStore(t)
	key := Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500}
	part0 := allowedPreviewPart0(1, 7, []byte{192, 0, 2, 1}, 100, 200)
	part1 := allowedPreviewPart1(1, 7, []byte{239, 1, 2, 3}, 60, 999)
	setTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable,
		append(part1, part0...))
	rows := getTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
	if rows.NumRows != 2 || binary.BigEndian.Uint16(rows.Rows[:2]) != 7 ||
		binary.BigEndian.Uint16(rows.Rows[multicastPreviewRowSize:]) != 1<<11|7 ||
		binary.BigEndian.Uint16(rows.Rows[multicastPreviewRowSize+20:]) != 60 {
		t.Fatalf("stored allowed-preview rows = %x", rows.Rows)
	}

	part1 = allowedPreviewPart1(1, 7, []byte{239, 1, 2, 3}, 90, 1)
	setTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable, part1)
	rows = getTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
	if got := binary.BigEndian.Uint16(rows.Rows[multicastPreviewRowSize+20:]); got != 90 {
		t.Fatalf("allowed-preview duration extension time left = %d, want 90", got)
	}

	setTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable,
		allowedPreviewControlRow(2, 1, 7))
	rows = getTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
	if rows.NumRows != 0 {
		t.Fatalf("allowed-preview delete did not remove both parts: %x", rows.Rows)
	}
}

func TestAllowedPreviewRuntimeOverlayAndAutonomousExpiry(t *testing.T) {
	var changes []Change
	store, err := NewWithApplier([]Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}, ApplyFunc(func(change Change) error {
		changes = append(changes, change)
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	key := Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500}
	if err := store.Create(key.ClassID, key.EntityID, me.AttributeValueMap{
		me.MulticastSubscriberConfigInfo_MeType:                            uint8(0),
		me.MulticastSubscriberConfigInfo_MulticastOperationsProfilePointer: uint16(0x700),
	}); err != nil {
		t.Fatalf("Create(multicast subscriber) error = %v", err)
	}
	timed := append(allowedPreviewPart0(1, 7, []byte{192, 0, 2, 1}, 100, 200),
		allowedPreviewPart1(1, 7, []byte{239, 1, 2, 3}, 60, 999)...)
	untimed := append(allowedPreviewPart0(1, 9, nil, 101, 201),
		allowedPreviewPart1(1, 9, []byte{239, 1, 2, 4}, 0, 999)...)
	setTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable, append(timed, untimed...))
	sync := store.DataSync()

	instance, err := store.Get(key, 0x0200)
	if err != nil {
		t.Fatalf("Get(allowed preview) error = %v", err)
	}
	overlay, err := OverlayAllowedPreviewTimers(instance, []AllowedPreviewTimer{
		{RowKey: 7, Duration: 60, TimeLeft: 23},
		{RowKey: 9, Duration: 0, TimeLeft: 0},
	})
	if err != nil {
		t.Fatalf("OverlayAllowedPreviewTimers() error = %v", err)
	}
	overlayRows := overlay.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable].(me.TableRows)
	if got := binary.BigEndian.Uint16(overlayRows.Rows[multicastPreviewRowSize+20:]); got != 23 {
		t.Fatalf("overlaid time left = %d, want 23", got)
	}
	committed := getTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
	if got := binary.BigEndian.Uint16(committed.Rows[multicastPreviewRowSize+20:]); got != 60 {
		t.Fatalf("overlay changed committed time left to %d", got)
	}

	changes = nil
	changed, err := store.ExpireAllowedPreviewRows(key, []AllowedPreviewTimer{
		{RowKey: 7, Duration: 60, TimeLeft: 0},
		{RowKey: 9, Duration: 0, TimeLeft: 0},
	})
	if err != nil || !changed {
		t.Fatalf("ExpireAllowedPreviewRows() = %t, %v", changed, err)
	}
	if store.DataSync() != sync || len(changes) != 1 || changes[0].Operation != OperationAutonomous ||
		changes[0].MIBDataSync != sync {
		t.Fatalf("autonomous expiry state = sync %d changes %+v, want sync %d", store.DataSync(), changes, sync)
	}
	committed = getTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
	if committed.NumRows != 2 || binary.BigEndian.Uint16(committed.Rows[:2]) != 9 ||
		binary.BigEndian.Uint16(committed.Rows[multicastPreviewRowSize:]) != 1<<11|9 {
		t.Fatalf("autonomous expiry did not remove exactly row 7: %x", committed.Rows)
	}
}

func TestAllowedPreviewAutonomousExpiryRollsBackOnPlatformFailure(t *testing.T) {
	reject := false
	store, err := NewWithApplier([]Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}, ApplyFunc(func(change Change) error {
		if reject && change.Operation == OperationAutonomous {
			return errors.New("platform unavailable")
		}
		return nil
	}))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	key := Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500}
	if err := store.Create(key.ClassID, key.EntityID, me.AttributeValueMap{
		me.MulticastSubscriberConfigInfo_MeType:                            uint8(0),
		me.MulticastSubscriberConfigInfo_MulticastOperationsProfilePointer: uint16(0x700),
	}); err != nil {
		t.Fatalf("Create(multicast subscriber) error = %v", err)
	}
	rows := append(allowedPreviewPart0(1, 7, nil, 100, 200),
		allowedPreviewPart1(1, 7, []byte{239, 1, 2, 3}, 60, 0)...)
	setTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable, rows)
	sync := store.DataSync()
	reject = true
	changed, err := store.ExpireAllowedPreviewRows(key,
		[]AllowedPreviewTimer{{RowKey: 7, Duration: 60, TimeLeft: 0}})
	if err == nil || changed {
		t.Fatalf("rejected ExpireAllowedPreviewRows() = %t, %v", changed, err)
	}
	committed := getTable(t, store, key, 0x0200,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
	if store.DataSync() != sync || committed.NumRows != 2 {
		t.Fatalf("rejected expiry changed state: sync=%d rows=%x", store.DataSync(), committed.Rows)
	}
}

func TestSetTableMulticastSubscriberRejectsInvalidRowsAtomically(t *testing.T) {
	serviceTests := []struct {
		name string
		row  []byte
	}{
		{name: "service control", row: multicastServiceRow(0, 1, 100, 1, 1, 0x700)},
		{name: "service reserved control", row: func() []byte {
			row := multicastServiceRow(1, 1, 100, 1, 1, 0x700)
			binary.BigEndian.PutUint16(row[:2], binary.BigEndian.Uint16(row[:2])|1<<10)
			return row
		}()},
		{name: "service VLAN", row: multicastServiceRow(1, 1, 4098, 1, 1, 0x700)},
		{name: "service profile", row: multicastServiceRow(1, 1, 100, 1, 1, 0)},
		{name: "service reserved", row: func() []byte {
			row := multicastServiceRow(1, 1, 100, 1, 1, 0x700)
			row[12] = 1
			return row
		}()},
	}
	for _, test := range serviceTests {
		t.Run(test.name, func(t *testing.T) {
			store := newMulticastSubscriberStore(t)
			err := store.SetTable(Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500},
				0x0400, me.AttributeValueMap{
					me.MulticastSubscriberConfigInfo_MulticastServicePackageTable: me.TableRows{
						NumRows: 1, Rows: test.row,
					},
				})
			assertRejectedEmptyTable(t, store, err, 0x0400,
				me.MulticastSubscriberConfigInfo_MulticastServicePackageTable)
		})
	}

	previewTests := []struct {
		name string
		row  []byte
	}{
		{name: "preview control", row: allowedPreviewPart0(0, 1, []byte{192, 0, 2, 1}, 1, 1)},
		{name: "preview part", row: allowedPreviewControlRow(1, 2, 1)},
		{name: "preview VLAN", row: allowedPreviewPart0(1, 1, []byte{192, 0, 2, 1}, 4096, 1)},
		{name: "preview destination", row: allowedPreviewPart1(1, 1, []byte{192, 0, 2, 1}, 1, 1)},
	}
	for _, test := range previewTests {
		t.Run(test.name, func(t *testing.T) {
			store := newMulticastSubscriberStore(t)
			err := store.SetTable(Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500},
				0x0200, me.AttributeValueMap{
					me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable: me.TableRows{
						NumRows: 1, Rows: test.row,
					},
				})
			assertRejectedEmptyTable(t, store, err, 0x0200,
				me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable)
		})
	}
}

func assertRejectedEmptyTable(t *testing.T, store *Store, err error, mask uint16, name string) {
	t.Helper()
	var result *ResultError
	if !errors.As(err, &result) || result.Result != me.ParameterError {
		t.Fatalf("SetTable() error = %#v, want ParameterError", err)
	}
	if store.DataSync() != 1 {
		t.Fatalf("DataSync() = %d after rejected row, want 1", store.DataSync())
	}
	rows := getTable(t, store,
		Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500}, mask, name)
	if rows.NumRows != 0 || len(rows.Rows) != 0 {
		t.Fatalf("rejected table committed rows: %x", rows.Rows)
	}
}

func newMulticastTableStore(t *testing.T) *Store {
	t.Helper()
	store, err := New([]Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Create(me.MulticastGemInterworkingTerminationPointClassID, 0x300,
		me.AttributeValueMap{
			me.MulticastGemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer: uint16(0x400),
			me.MulticastGemInterworkingTerminationPoint_InterworkingOption:                   uint8(1),
			me.MulticastGemInterworkingTerminationPoint_ServiceProfilePointer:                uint16(0x100),
			me.MulticastGemInterworkingTerminationPoint_NotUsed1:                             uint16(0),
			me.MulticastGemInterworkingTerminationPoint_GalProfilePointer:                    uint16(0),
			me.MulticastGemInterworkingTerminationPoint_NotUsed2:                             uint8(0),
		}); err != nil {
		t.Fatalf("Create(multicast GEM IW) error = %v", err)
	}
	return store
}

func newMulticastOperationsStore(t *testing.T) *Store {
	t.Helper()
	store, err := New([]Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Create(me.MulticastOperationsProfileClassID, 0x700, me.AttributeValueMap{
		me.MulticastOperationsProfile_IgmpVersion:    uint8(3),
		me.MulticastOperationsProfile_IgmpFunction:   uint8(0),
		me.MulticastOperationsProfile_ImmediateLeave: uint8(0),
	}); err != nil {
		t.Fatalf("Create(multicast operations profile) error = %v", err)
	}
	return store
}

func newMulticastSubscriberStore(t *testing.T) *Store {
	t.Helper()
	store, err := New([]Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Create(me.MulticastSubscriberConfigInfoClassID, 0x500, me.AttributeValueMap{
		me.MulticastSubscriberConfigInfo_MeType:                            uint8(0),
		me.MulticastSubscriberConfigInfo_MulticastOperationsProfilePointer: uint16(0x700),
	}); err != nil {
		t.Fatalf("Create(multicast subscriber) error = %v", err)
	}
	return store
}

func newExtendedVLANStore(t *testing.T, options Options) *Store {
	t.Helper()
	factory := []Instance{{
		Key:        Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}
	store, err := NewWithOptions(factory, options)
	if err != nil {
		t.Fatalf("NewWithOptions() error = %v", err)
	}
	if err := store.Create(me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		extendedVLANEntityID, me.AttributeValueMap{
			me.ExtendedVlanTaggingOperationConfigurationData_AssociationType:     uint8(2),
			me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer: uint16(0x101),
			me.ExtendedVlanTaggingOperationConfigurationData_EnhancedMode:        uint8(1),
		}); err != nil {
		t.Fatalf("Create(extended VLAN) error = %v", err)
	}
	return store
}

func snapshotInstance(t *testing.T, store *Store, key Key) Instance {
	t.Helper()
	for _, instance := range store.Snapshot() {
		if instance.Key == key {
			return instance
		}
	}
	t.Fatalf("snapshot does not contain %#v", key)
	return Instance{}
}

func getTable(t *testing.T, store *Store, key Key, mask uint16, name string) me.TableRows {
	t.Helper()
	instance, err := store.Get(key, mask)
	if err != nil {
		t.Fatalf("Get(%s) error = %v", name, err)
	}
	rows, ok := instance.Attributes[name].(me.TableRows)
	if !ok {
		t.Fatalf("%s = %#v, want TableRows", name, instance.Attributes[name])
	}
	return rows
}

func setTable(t *testing.T, store *Store, key Key, mask uint16, name string, rows []byte) {
	t.Helper()
	definition, omciErr := me.GetAttributesDefinitions(key.ClassID)
	if omciErr.StatusCode() != me.Success {
		t.Fatalf("GetAttributesDefinitions() error = %v", omciErr.GetError())
	}
	attribute, err := me.GetAttributeDefinitionByName(definition, name)
	if err != nil {
		t.Fatalf("GetAttributeDefinitionByName() error = %v", err)
	}
	if err := store.SetTable(key, mask, me.AttributeValueMap{name: me.TableRows{
		NumRows: len(rows) / attribute.GetSize(),
		Rows:    rows,
	}}); err != nil {
		t.Fatalf("SetTable(%s) error = %v", name, err)
	}
}

func classicVLANRow(key, treatment byte) []byte {
	row := make([]byte, extendedVLANRowSize)
	row[7] = key
	row[15] = treatment
	return row
}

func enhancedVLANRow(control, direction byte, key uint16, treatment byte) []byte {
	row := make([]byte, enhancedExtendedVLANRowSize)
	row[0] = control<<6 | direction<<4
	binary.BigEndian.PutUint16(row[2:4], key)
	row[19] = treatment
	return row
}

func multicastIPv4Row(gem, secondary uint16, start, stop uint32) []byte {
	row := make([]byte, multicastIPv4RowSize)
	binary.BigEndian.PutUint16(row[0:2], gem)
	binary.BigEndian.PutUint16(row[2:4], secondary)
	binary.BigEndian.PutUint32(row[4:8], start)
	binary.BigEndian.PutUint32(row[8:12], stop)
	return row
}

func multicastIPv6Row(gem, secondary uint16, start, stop uint32) []byte {
	row := make([]byte, multicastIPv6RowSize)
	binary.BigEndian.PutUint16(row[0:2], gem)
	binary.BigEndian.PutUint16(row[2:4], secondary)
	binary.BigEndian.PutUint32(row[4:8], start)
	binary.BigEndian.PutUint32(row[8:12], stop)
	row[12] = 0xff
	return row
}

func multicastACLControlRow(setControl, part uint16, key uint16) []byte {
	row := make([]byte, multicastACLRowSize)
	binary.BigEndian.PutUint16(row[:2], setControl<<14|part<<11|key)
	return row
}

func multicastACLPart0(setControl, key, gem, vlan uint16, start, stop uint32) []byte {
	row := multicastACLControlRow(setControl, 0, key)
	binary.BigEndian.PutUint16(row[2:4], gem)
	binary.BigEndian.PutUint16(row[4:6], vlan)
	binary.BigEndian.PutUint32(row[10:14], start)
	binary.BigEndian.PutUint32(row[14:18], stop)
	binary.BigEndian.PutUint32(row[18:22], 1_000_000)
	return row
}

func multicastACLPart1(setControl, key, reset uint16) []byte {
	row := multicastACLControlRow(setControl, 1, key)
	binary.BigEndian.PutUint16(row[20:22], reset)
	return row
}

func multicastACLPart2(setControl, key uint16, prefix []byte) []byte {
	row := multicastACLControlRow(setControl, 2, key)
	copy(row[2:14], prefix)
	return row
}

func multicastServiceControlRow(setControl, key uint16) []byte {
	row := make([]byte, multicastServiceRowSize)
	binary.BigEndian.PutUint16(row[:2], setControl<<14|key)
	return row
}

func multicastServiceRow(setControl, key, vlan, groups uint16, bandwidth uint32, profile uint16) []byte {
	row := multicastServiceControlRow(setControl, key)
	binary.BigEndian.PutUint16(row[2:4], vlan)
	binary.BigEndian.PutUint16(row[4:6], groups)
	binary.BigEndian.PutUint32(row[6:10], bandwidth)
	binary.BigEndian.PutUint16(row[10:12], profile)
	return row
}

func allowedPreviewControlRow(setControl, part, key uint16) []byte {
	row := make([]byte, multicastPreviewRowSize)
	binary.BigEndian.PutUint16(row[:2], setControl<<14|part<<11|key)
	return row
}

func allowedPreviewPart0(setControl, key uint16, source []byte, aniVLAN, uniVLAN uint16) []byte {
	row := allowedPreviewControlRow(setControl, 0, key)
	copy(row[18-len(source):18], source)
	binary.BigEndian.PutUint16(row[18:20], aniVLAN)
	binary.BigEndian.PutUint16(row[20:22], uniVLAN)
	return row
}

func allowedPreviewPart1(setControl, key uint16, destination []byte, duration, timeLeft uint16) []byte {
	row := allowedPreviewControlRow(setControl, 1, key)
	copy(row[18-len(destination):18], destination)
	binary.BigEndian.PutUint16(row[18:20], duration)
	binary.BigEndian.PutUint16(row[20:22], timeLeft)
	return row
}

func tableRowsEqual(value interface{}, want me.TableRows) bool {
	got, ok := value.(me.TableRows)
	return ok && got.NumRows == want.NumRows && bytes.Equal(got.Rows, want.Rows)
}

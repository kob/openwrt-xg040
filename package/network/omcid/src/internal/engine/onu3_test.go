// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/onu3"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

func TestONU3DefinitionSupportsRequiredProtocolSurface(t *testing.T) {
	entity, omciErr := me.LoadManagedEntityDefinition(me.Onu3GClassID, me.ParamData{EntityID: 0})
	if omciErr.StatusCode() != me.Success {
		t.Fatal(omciErr.GetError())
	}
	for _, action := range []me.MsgType{me.Get, me.GetNext, me.Set} {
		if !me.SupportsMsgType(entity, action) {
			t.Fatalf("ONU3-G definition does not support %v", action)
		}
	}
	definitions := entity.GetAttributeDefinitions()
	table, err := me.GetAttributeDefinitionByName(definitions, me.Onu3G_StatusSnapshotRecordTable)
	if err != nil || !table.IsTableAttribute() || table.GetSize() != onu3.RecordSize {
		t.Fatalf("ONU3-G status table definition = %#v, error = %v", table, err)
	}
	for _, name := range []string{
		me.Onu3G_NumberOfValidStatusSnapshots,
		me.Onu3G_NextStatusSnapshotIndex,
	} {
		definition, err := me.GetAttributeDefinitionByName(definitions, name)
		if err != nil || !definition.Avc {
			t.Fatalf("ONU3-G %s AVC definition = %#v, error = %v", name, definition, err)
		}
	}
	total, err := me.GetAttributeDefinitionByName(definitions, me.Onu3G_TotalNumberOfStatusSnapshots)
	if err != nil || total.Avc {
		t.Fatalf("ONU3-G total snapshot AVC definition = %#v, error = %v", total, err)
	}
}

func TestONU3SnapResetAndTableTransfer(t *testing.T) {
	for name, device := range map[string]omci.DeviceIdent{
		"baseline": omci.BaselineIdent,
		"extended": omci.ExtendedIdent,
	} {
		t.Run(name, func(t *testing.T) {
			protocol, store := newONU3Engine(t, nil)
			takenAt := time.Date(2026, time.August, 11, 1, 2, 3, 0, time.UTC)
			protocol.now = func() time.Time { return takenAt }
			var alarm [28]byte
			alarm[0] = 0x80
			protocol.SetAlarm(mib.Key{ClassID: me.OnuGClassID}, alarm)

			set := encodeONU3Set(t, 1, device, me.AttributeValueMap{
				me.Onu3G_SnapAction: uint8(1),
			})
			encoded, err := protocol.Handle(set)
			if err != nil {
				t.Fatalf("Handle(ONU3-G Snap) error = %v", err)
			}
			response := decodeResponse(t, encoded).Layer(omci.LayerTypeSetResponse).(*omci.SetResponse)
			if response.Result != me.Success || store.DataSync() != 1 {
				t.Fatalf("Snap result/sync = %v/%d", response.Result, store.DataSync())
			}
			assertONU3AVC(t, protocol.DrainNotifications(), 1, 1)

			getRecent := encodeONU3Get(t, 2, device, 0x0100)
			encoded, err = protocol.Handle(getRecent)
			if err != nil {
				t.Fatalf("Handle(ONU3-G recent Get) error = %v", err)
			}
			getResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
			record, valid := getResponse.Attributes[me.Onu3G_MostRecentStatusSnapshot].([]byte)
			if getResponse.Result != me.Success || !valid || len(record) != onu3.RecordSize {
				t.Fatalf("recent Get response = %#v", getResponse)
			}
			if record[0] != onu3.FormatVersion || record[1] != onu3.TriggerOLTSnap ||
				binary.BigEndian.Uint64(record[2:10]) != uint64(takenAt.Unix()) ||
				record[10] != 0 || binary.BigEndian.Uint16(record[13:15]) != 1 ||
				(record[15]&onu3.FlagExtendedOMCI != 0) != (device == omci.ExtendedIdent) {
				t.Fatalf("status snapshot record = %x", record)
			}

			getTable := encodeONU3Get(t, 3, device, 0x0400)
			encoded, err = protocol.Handle(getTable)
			if err != nil {
				t.Fatalf("Handle(ONU3-G table Get) error = %v", err)
			}
			tableResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
			if tableResponse.Result != me.Success ||
				tableResponse.Attributes[me.Onu3G_StatusSnapshotRecordTable] != uint32(onu3.RecordSize) {
				t.Fatalf("status table Get response = %#v", tableResponse)
			}

			next := encodeRequestForDevice(t, 4, omci.GetNextRequestType, &omci.GetNextRequest{
				MeBasePacket: omci.MeBasePacket{
					EntityClass: me.Onu3GClassID, Extended: device == omci.ExtendedIdent,
				},
				AttributeMask: 0x0400,
			}, device)
			encoded, err = protocol.Handle(next)
			if err != nil {
				t.Fatalf("Handle(ONU3-G Get Next) error = %v", err)
			}
			nextResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetNextResponse).(*omci.GetNextResponse)
			rows, valid := nextResponse.Attributes[me.Onu3G_StatusSnapshotRecordTable].([]byte)
			if nextResponse.Result != me.Success || !valid || len(rows) < onu3.RecordSize ||
				!bytes.Equal(rows[:onu3.RecordSize], record) {
				t.Fatalf("status table Get Next response = %#v", nextResponse)
			}

			reset := encodeONU3Set(t, 5, device, me.AttributeValueMap{
				me.Onu3G_ResetAction: uint8(1),
			})
			encoded, err = protocol.Handle(reset)
			if err != nil {
				t.Fatalf("Handle(ONU3-G Reset) error = %v", err)
			}
			response = decodeResponse(t, encoded).Layer(omci.LayerTypeSetResponse).(*omci.SetResponse)
			if response.Result != me.Success || store.DataSync() != 2 {
				t.Fatalf("Reset result/sync = %v/%d", response.Result, store.DataSync())
			}
			assertONU3AVC(t, protocol.DrainNotifications(), 0, 0)
			state := getONU3State(t, store)
			if state.valid != 0 || state.next != 0 || state.table.NumRows != 0 ||
				len(state.table.Rows) != 0 || !bytes.Equal(state.recent, make([]byte, onu3.RecordSize)) {
				t.Fatalf("ONU3-G state after Reset = %#v", state)
			}
		})
	}
}

func TestONU3CircularBufferReplayAndMIBReset(t *testing.T) {
	protocol, store := newONU3Engine(t, nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	protocol.now = func() time.Time { return now }

	first := encodeONU3Set(t, 1, omci.BaselineIdent, me.AttributeValueMap{
		me.Onu3G_SnapAction: uint8(1),
	})
	firstResponse, err := protocol.Handle(first)
	if err != nil {
		t.Fatal(err)
	}
	protocol.DrainNotifications()
	replayed, err := protocol.Handle(first)
	if err != nil || !bytes.Equal(replayed, firstResponse) || store.DataSync() != 1 ||
		len(protocol.DrainNotifications()) != 0 {
		t.Fatalf("replayed Snap changed state: error=%v sync=%d", err, store.DataSync())
	}

	for index := 1; index < onu3.SnapshotCapacity+1; index++ {
		now = now.Add(time.Second)
		request := encodeONU3Set(t, uint16(index+1), omci.BaselineIdent, me.AttributeValueMap{
			me.Onu3G_SnapAction: uint8(1),
		})
		if _, err := protocol.Handle(request); err != nil {
			t.Fatalf("Handle(Snap %d) error = %v", index+1, err)
		}
		protocol.DrainNotifications()
	}
	state := getONU3State(t, store)
	if store.DataSync() != 17 || state.valid != onu3.SnapshotCapacity || state.next != 1 ||
		state.table.NumRows != onu3.SnapshotCapacity ||
		len(state.table.Rows) != onu3.SnapshotCapacity*onu3.RecordSize ||
		!bytes.Equal(state.recent, state.table.Rows[:onu3.RecordSize]) ||
		binary.BigEndian.Uint64(state.table.Rows[2:10]) != uint64(now.Unix()) {
		t.Fatalf("wrapped ONU3-G state: sync=%d state=%#v", store.DataSync(), state)
	}

	reset := encodeRequest(t, 100, omci.MibResetRequestType, &omci.MibResetRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID},
	})
	encoded, err := protocol.Handle(reset)
	if err != nil {
		t.Fatalf("Handle(MIB reset) error = %v", err)
	}
	resetResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeMibResetResponse).(*omci.MibResetResponse)
	after := getONU3State(t, store)
	if resetResponse.Result != me.Success || store.DataSync() != 0 ||
		after.valid != state.valid || after.next != state.next ||
		!bytes.Equal(after.table.Rows, state.table.Rows) || !bytes.Equal(after.recent, state.recent) {
		t.Fatalf("MIB reset did not preserve ONU3-G: result=%v sync=%d after=%#v",
			resetResponse.Result, store.DataSync(), after)
	}
}

func TestONU3CommandApplyFailureDoesNotCommit(t *testing.T) {
	wantError := errors.New("persistent store unavailable")
	protocol, store := newONU3Engine(t, mib.ApplyFunc(func(change mib.Change) error {
		if change.Operation == mib.OperationCommand {
			return wantError
		}
		return nil
	}))
	request := encodeONU3Set(t, 1, omci.BaselineIdent, me.AttributeValueMap{
		me.Onu3G_SnapAction: uint8(1),
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(rejected Snap) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeSetResponse).(*omci.SetResponse)
	state := getONU3State(t, store)
	if response.Result != me.ProcessingError || store.DataSync() != 0 || state.valid != 0 ||
		state.next != 0 || state.table.NumRows != 0 || len(protocol.DrainNotifications()) != 0 {
		t.Fatalf("rejected Snap committed state: response=%#v sync=%d state=%#v",
			response, store.DataSync(), state)
	}
}

func TestONU3RejectsAmbiguousAction(t *testing.T) {
	protocol, store := newONU3Engine(t, nil)
	request := encodeONU3Set(t, 1, omci.BaselineIdent, me.AttributeValueMap{
		me.Onu3G_SnapAction:  uint8(1),
		me.Onu3G_ResetAction: uint8(1),
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(ambiguous action) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeSetResponse).(*omci.SetResponse)
	if response.Result != me.ParameterError || store.DataSync() != 0 {
		t.Fatalf("ambiguous action result/sync = %v/%d", response.Result, store.DataSync())
	}
}

type onu3State struct {
	valid  uint16
	next   uint16
	table  me.TableRows
	recent []byte
}

func newONU3Engine(t *testing.T, applier mib.Applier) (*Engine, *mib.Store) {
	t.Helper()
	factory, err := model.XG2010G(model.Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := model.XG2010GSupportedAttributeMasks(pon.GPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := mib.NewWithOptions(factory, mib.Options{
		Applier: applier, SupportedClasses: model.XG2010GSupportedClasses(pon.GPON),
		SupportedAttributeMasks: masks, ValidateInstance: model.XG2010GInstanceValidator(pon.GPON),
		AttributeCapabilities: model.XG2010GAttributeCapabilities(pon.GPON),
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(store), store
}

func encodeONU3Set(t *testing.T, transactionID uint16, device omci.DeviceIdent,
	attributes me.AttributeValueMap) []byte {
	t.Helper()
	var mask uint16
	for name := range attributes {
		mask |= onu3AttributeMask(name)
	}
	return encodeRequestForDevice(t, transactionID, omci.SetRequestType, &omci.SetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.Onu3GClassID, Extended: device == omci.ExtendedIdent,
		},
		AttributeMask: mask,
		Attributes:    attributes,
	}, device)
}

func encodeONU3Get(t *testing.T, transactionID uint16, device omci.DeviceIdent, mask uint16) []byte {
	t.Helper()
	return encodeRequestForDevice(t, transactionID, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.Onu3GClassID, Extended: device == omci.ExtendedIdent,
		},
		AttributeMask: mask,
	}, device)
}

func assertONU3AVC(t *testing.T, frames [][]byte, valid, next uint16) {
	t.Helper()
	if len(frames) != 1 {
		t.Fatalf("ONU3-G AVC frame count = %d, want 1", len(frames))
	}
	avc := decodeResponse(t, frames[0]).Layer(omci.LayerTypeAttributeValueChange).(*omci.AttributeValueChangeMsg)
	if avc.EntityClass != me.Onu3GClassID || avc.EntityInstance != 0 || avc.AttributeMask != 0x1800 ||
		avc.Attributes[me.Onu3G_NumberOfValidStatusSnapshots] != valid ||
		avc.Attributes[me.Onu3G_NextStatusSnapshotIndex] != next {
		t.Fatalf("ONU3-G AVC = %#v", avc)
	}
}

func getONU3State(t *testing.T, store *mib.Store) onu3State {
	t.Helper()
	instance, err := store.Get(mib.Key{ClassID: me.Onu3GClassID}, onu3SnapshotStateMask)
	if err != nil {
		t.Fatalf("Get(ONU3-G state) error = %v", err)
	}
	return onu3State{
		valid:  instance.Attributes[me.Onu3G_NumberOfValidStatusSnapshots].(uint16),
		next:   instance.Attributes[me.Onu3G_NextStatusSnapshotIndex].(uint16),
		table:  instance.Attributes[me.Onu3G_StatusSnapshotRecordTable].(me.TableRows),
		recent: instance.Attributes[me.Onu3G_MostRecentStatusSnapshot].([]byte),
	}
}

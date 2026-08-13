// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/engine"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/platform"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

const daemonTestStateDomain = "xg2010g:gpon"

func TestRuntimeStateWriterPublishesOnlyChangesAndRestores(t *testing.T) {
	protocol, key := daemonRuntimeEngine(t)
	path := filepath.Join(t.TempDir(), "persistent", "runtime.json")
	writer := newRuntimeStateWriter(path)
	written, err := writer.Write(protocol)
	if err != nil || !written {
		t.Fatalf("first Write() written=%t error=%v", written, err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	written, err = writer.Write(protocol)
	if err != nil || written {
		t.Fatalf("unchanged Write() written=%t error=%v", written, err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Fatalf("unchanged runtime state rewrote the file")
	}

	var alarm [28]byte
	alarm[0] = 0x80
	if _, emitted, err := protocol.NotifyAlarm(key, alarm, omci.BaselineIdent); err != nil || !emitted {
		t.Fatalf("NotifyAlarm() emitted=%t error=%v", emitted, err)
	}
	written, err = writer.Write(protocol)
	if err != nil || !written {
		t.Fatalf("changed Write() written=%t error=%v", written, err)
	}
	restored, _ := daemonRuntimeEngine(t)
	if err := restoreRuntimeState(restored, path); err != nil {
		t.Fatalf("restoreRuntimeState() error = %v", err)
	}
	if frame, emitted, err := restored.NotifyAlarm(key, alarm, omci.BaselineIdent); err != nil || emitted || frame != nil {
		t.Fatalf("restored duplicate alarm frame=%x emitted=%t error=%v", frame, emitted, err)
	}
}

func TestRestoreRuntimeStateRejectsUnknownAndTrailingJSON(t *testing.T) {
	protocol, _ := daemonRuntimeEngine(t)
	for name, document := range map[string]string{
		"unknown":  `{"version":1,"unknown":true}`,
		"trailing": `{}` + "\n{}",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime.json")
			if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := restoreRuntimeState(protocol, path); err == nil ||
				(name == "unknown" && !strings.Contains(err.Error(), "unknown field")) ||
				(name == "trailing" && !strings.Contains(err.Error(), "trailing")) {
				t.Fatalf("restoreRuntimeState(%s) error = %v", name, err)
			}
		})
	}
}

func daemonRuntimeEngine(t *testing.T) (*engine.Engine, mib.Key) {
	t.Helper()
	factory := daemonTestFactory(t, "ABCD01020304")
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID,
		EntityID: 0x0101}
	store, err := mib.New(factory)
	if err != nil {
		t.Fatal(err)
	}
	return engine.New(store), key
}

func TestInitializeMIBRestoresCommittedState(t *testing.T) {
	factory := daemonTestFactory(t, "ABCD01020304")
	committed, err := mib.New(factory)
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	if err := committed.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	statePath := writeDaemonState(t, committed)
	applyCalls := 0
	restored, err := initializeMIB(pon.GPON, daemonTestStateDomain, factory, mib.ApplyFunc(func(mib.Change) error {
		applyCalls++
		return nil
	}), statePath)
	if err != nil {
		t.Fatalf("initializeMIB() error = %v", err)
	}
	if applyCalls != 0 || restored.DataSync() != 1 ||
		!restored.Exists(mib.Key{ClassID: me.GalEthernetProfileClassID, EntityID: 1}) {
		t.Fatalf("restored state: calls=%d sync=%d exists=%t",
			applyCalls, restored.DataSync(),
			restored.Exists(mib.Key{ClassID: me.GalEthernetProfileClassID, EntityID: 1}))
	}
}

func TestInitializeMIBResetsStateForDifferentONU(t *testing.T) {
	committedFactory := daemonTestFactory(t, "ABCD01020304")
	committed, err := mib.New(committedFactory)
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	statePath := writeDaemonState(t, committed)
	var changes []mib.Change
	restored, err := initializeMIB(pon.GPON, daemonTestStateDomain,
		daemonTestFactory(t, "WXYZ01020304"),
		mib.ApplyFunc(func(change mib.Change) error {
			changes = append(changes, change)
			return nil
		}), statePath)
	if err != nil {
		t.Fatalf("initializeMIB() error = %v", err)
	}
	if len(changes) != 1 || changes[0].Operation != mib.OperationReset || restored.DataSync() != 0 {
		t.Fatalf("identity reset changes=%+v sync=%d", changes, restored.DataSync())
	}
}

func TestInitializeMIBResetsMismatchedServiceGraph(t *testing.T) {
	factory := daemonTestFactory(t, "ABCD01020304")
	committed, err := mib.New(factory)
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	state, err := mib.ExportState(committed.Snapshot(), committed.DataSync(), daemonTestStateDomain)
	if err != nil {
		t.Fatalf("ExportState() error = %v", err)
	}
	graph, err := platform.BuildServiceGraph(committed.Snapshot())
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	graph.UNIs = nil
	statePath := writeDaemonRequest(t, platform.ApplyRequest{
		Version: platform.ApplyABIVersion, StateDomain: daemonTestStateDomain,
		Operation:   mib.OperationSet,
		MIBDataSync: state.MIBDataSync, MIBState: &state, Service: graph,
	})
	applyCalls := 0
	_, err = initializeMIB(pon.GPON, daemonTestStateDomain, factory, mib.ApplyFunc(func(mib.Change) error {
		applyCalls++
		return nil
	}), statePath)
	if err != nil {
		t.Fatalf("initializeMIB() error = %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("mismatched graph caused %d apply calls, want factory reset", applyCalls)
	}
}

func TestRestoreONU3FactoryLoadsPersistentSnapshots(t *testing.T) {
	persisted, err := mib.New(daemonTestFactory(t, "ABCD01020304"))
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 25)
	record[0] = 1
	if err := persisted.UpdateByCommand(map[mib.Key]me.AttributeValueMap{
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
	persistentPath := writeDaemonState(t, persisted)
	currentFactory, err := model.XG2010G(model.Identity{
		SerialNumber: "ABCD01020304", Version: "test", RestartReason: 9, PONMode: pon.GPON,
	})
	if err != nil {
		t.Fatal(err)
	}
	restoredFactory, err := restoreONU3Factory(currentFactory, persistentPath, daemonTestStateDomain)
	if err != nil {
		t.Fatalf("restoreONU3Factory() error = %v", err)
	}
	restored, err := mib.New(restoredFactory)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := restored.Get(mib.Key{ClassID: me.Onu3GClassID}, 0x5d00)
	if err != nil {
		t.Fatal(err)
	}
	if instance.Attributes[me.Onu3G_LatestRestartReason] != uint8(9) ||
		instance.Attributes[me.Onu3G_NumberOfValidStatusSnapshots] != uint16(1) ||
		instance.Attributes[me.Onu3G_NextStatusSnapshotIndex] != uint16(1) ||
		!bytes.Equal(instance.Attributes[me.Onu3G_MostRecentStatusSnapshot].([]byte), record) {
		t.Fatalf("restored ONU3-G = %#v", instance.Attributes)
	}
}

func daemonTestFactory(t *testing.T, serial string) []mib.Instance {
	t.Helper()
	factory, err := model.XG2010G(model.Identity{
		SerialNumber: serial, Version: "test", PONMode: pon.GPON,
	})
	if err != nil {
		t.Fatalf("model.XG2010G() error = %v", err)
	}
	return factory
}

func writeDaemonState(t *testing.T, store *mib.Store) string {
	t.Helper()
	state, err := mib.ExportState(store.Snapshot(), store.DataSync(), daemonTestStateDomain)
	if err != nil {
		t.Fatalf("ExportState() error = %v", err)
	}
	graph, err := platform.BuildServiceGraph(store.Snapshot())
	if err != nil {
		t.Fatalf("BuildServiceGraph() error = %v", err)
	}
	return writeDaemonRequest(t, platform.ApplyRequest{
		Version: platform.ApplyABIVersion, StateDomain: daemonTestStateDomain,
		Operation:   mib.OperationSet,
		MIBDataSync: state.MIBDataSync, MIBState: &state, Service: graph,
	})
}

func writeDaemonRequest(t *testing.T, request platform.ApplyRequest) string {
	t.Helper()
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	return path
}

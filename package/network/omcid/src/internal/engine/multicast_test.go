// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/multicast"
)

type recordingMulticastController struct {
	*recordingController
	entity          uint16
	monitor         multicast.Monitor
	err             error
	preview         multicast.AllowedPreviewSnapshot
	previewErr      error
	previewRequests int
}

func (c *recordingMulticastController) SubscriberMonitor(entityID uint16) (multicast.Monitor, error) {
	c.entity = entityID
	return c.monitor, c.err
}

func (c *recordingMulticastController) AllowedPreviewStatus(entityID uint16) (multicast.AllowedPreviewSnapshot, error) {
	c.entity = entityID
	c.previewRequests++
	return c.preview, c.previewErr
}

func TestGetMulticastSubscriberMonitorUsesLiveBackend(t *testing.T) {
	const entityID = 0x0500
	controller := &recordingMulticastController{
		recordingController: &recordingController{},
		monitor: multicast.Monitor{
			CurrentBandwidth: 3_000_000, JoinMessages: 17, BandwidthExceeded: 2,
			Groups: []multicast.ActiveGroup{{
				Source:  netip.MustParseAddr("198.51.100.1"),
				Group:   netip.MustParseAddr("239.1.2.3"),
				Client:  netip.MustParseAddr("192.0.2.10"),
				ANIVLAN: 100, ImputedBandwidth: 3_000_000, TimeSinceJoin: 45,
			}},
		},
	}
	protocol := newMulticastMonitorEngine(t, controller, entityID)
	request := encodeRequest(t, 0x700, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.MulticastSubscriberMonitorClassID, EntityInstance: entityID,
		},
		AttributeMask: 0x7000,
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Get multicast counters) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.Success || controller.entity != entityID ||
		response.Attributes[me.MulticastSubscriberMonitor_CurrentMulticastBandwidth] != uint32(3_000_000) ||
		response.Attributes[me.MulticastSubscriberMonitor_JoinMessagesCounter] != uint32(17) ||
		response.Attributes[me.MulticastSubscriberMonitor_BandwidthExceededCounter] != uint32(2) {
		t.Fatalf("multicast monitor response = %#v", response)
	}

	request = encodeRequest(t, 0x701, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.MulticastSubscriberMonitorClassID, EntityInstance: entityID,
		},
		AttributeMask: multicastMonitorIPv4TableMask,
	})
	encoded, err = protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Get multicast table) error = %v", err)
	}
	response = decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if got := response.Attributes[me.MulticastSubscriberMonitor_Ipv4ActiveGroupListTable]; got != uint32(24) {
		t.Fatalf("IPv4 active-group table size = %#v, want 24", got)
	}

	next := encodeRequest(t, 0x702, omci.GetNextRequestType, &omci.GetNextRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.MulticastSubscriberMonitorClassID, EntityInstance: entityID,
		},
		AttributeMask: multicastMonitorIPv4TableMask, SequenceNumber: 0,
	})
	encoded, err = protocol.Handle(next)
	if err != nil {
		t.Fatalf("Handle(GetNext multicast table) error = %v", err)
	}
	nextResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetNextResponse).(*omci.GetNextResponse)
	row, ok := nextResponse.Attributes[me.MulticastSubscriberMonitor_Ipv4ActiveGroupListTable].([]byte)
	if !ok || len(row) < 24 || binary.BigEndian.Uint16(row[0:2]) != 100 ||
		netip.AddrFrom4([4]byte(row[2:6])) != netip.MustParseAddr("198.51.100.1") ||
		netip.AddrFrom4([4]byte(row[6:10])) != netip.MustParseAddr("239.1.2.3") ||
		binary.BigEndian.Uint32(row[10:14]) != 3_000_000 ||
		netip.AddrFrom4([4]byte(row[14:18])) != netip.MustParseAddr("192.0.2.10") ||
		binary.BigEndian.Uint32(row[18:22]) != 45 {
		t.Fatalf("IPv4 active-group row = %x", row)
	}
}

func TestMulticastMonitorIPv6TableSupportsMixedClientAddress(t *testing.T) {
	_, ipv6, err := multicastMonitorTables([]multicast.ActiveGroup{{
		Source: netip.MustParseAddr("2001:db8::1"), Group: netip.MustParseAddr("ff3e::100"),
		Client: netip.MustParseAddr("192.0.2.10"), ANIVLAN: 200,
		ImputedBandwidth: 1234, TimeSinceJoin: 90,
	}})
	if err != nil {
		t.Fatalf("multicastMonitorTables() error = %v", err)
	}
	if ipv6.NumRows != 1 || len(ipv6.Rows) != 58 ||
		binary.BigEndian.Uint16(ipv6.Rows[0:2]) != 200 ||
		netip.AddrFrom16([16]byte(ipv6.Rows[2:18])) != netip.MustParseAddr("2001:db8::1") ||
		netip.AddrFrom16([16]byte(ipv6.Rows[18:34])) != netip.MustParseAddr("ff3e::100") ||
		binary.BigEndian.Uint32(ipv6.Rows[34:38]) != 1234 ||
		netip.AddrFrom4([4]byte(ipv6.Rows[50:54])) != netip.MustParseAddr("192.0.2.10") ||
		binary.BigEndian.Uint32(ipv6.Rows[54:58]) != 90 {
		t.Fatalf("IPv6 active-group rows = %x", ipv6.Rows)
	}
}

func TestGetMulticastMonitorReportsBackendFailure(t *testing.T) {
	const entityID = 0x0500
	controller := &recordingMulticastController{
		recordingController: &recordingController{}, err: errors.New("runtime unavailable"),
	}
	protocol := newMulticastMonitorEngine(t, controller, entityID)
	request := encodeRequest(t, 0x710, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.MulticastSubscriberMonitorClassID, EntityInstance: entityID,
		},
		AttributeMask: multicastMonitorCurrentBandwidthMask,
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Get failed multicast monitor) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.ProcessingError || response.AttributeMask != 0 {
		t.Fatalf("failed multicast monitor response = %#v", response)
	}
}

func TestAllowedPreviewGetUsesLiveTimerAndGetNextSnapshot(t *testing.T) {
	controller := &recordingMulticastController{recordingController: &recordingController{}}
	protocol, store, _ := newAllowedPreviewEngine(t, controller, nil)
	controller.preview = multicast.AllowedPreviewSnapshot{
		MIBDataSync: store.DataSync(),
		Timers:      []multicast.AllowedPreviewTimer{{RowKey: 7, Duration: 60, TimeLeft: 23}},
	}
	request := encodeRequestForDevice(t, 0x720, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.MulticastSubscriberConfigInfoClassID, EntityInstance: 0x500, Extended: true,
		},
		AttributeMask: multicastSubscriberAllowedPreviewMask,
	}, omci.ExtendedIdent)
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Get allowed-preview table) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.Success ||
		response.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable] != uint32(44) {
		t.Fatalf("allowed-preview Get response = %#v", response)
	}

	controller.preview.Timers[0].TimeLeft = 22
	next := encodeRequestForDevice(t, 0x721, omci.GetNextRequestType, &omci.GetNextRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.MulticastSubscriberConfigInfoClassID, EntityInstance: 0x500, Extended: true,
		},
		AttributeMask: multicastSubscriberAllowedPreviewMask,
	}, omci.ExtendedIdent)
	encoded, err = protocol.Handle(next)
	if err != nil {
		t.Fatalf("Handle(GetNext allowed-preview table) error = %v", err)
	}
	nextResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetNextResponse).(*omci.GetNextResponse)
	rows, ok := nextResponse.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable].([]byte)
	if !ok || len(rows) != 44 || binary.BigEndian.Uint16(rows[42:44]) != 23 {
		t.Fatalf("allowed-preview GetNext rows = %x", rows)
	}
	if controller.previewRequests != 1 {
		t.Fatalf("GetNext refreshed live timer %d times, want one Get-time snapshot", controller.previewRequests)
	}
	committed, err := store.Get(mib.Key{
		ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500,
	}, multicastSubscriberAllowedPreviewMask)
	if err != nil {
		t.Fatalf("Get(committed allowed-preview table) error = %v", err)
	}
	committedRows := committed.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable].(me.TableRows)
	if binary.BigEndian.Uint16(committedRows.Rows[42:44]) != 60 {
		t.Fatalf("live Get changed committed time left: %x", committedRows.Rows)
	}
}

func TestAllowedPreviewPollIgnoresStaleStateAndExpiresWithoutDataSync(t *testing.T) {
	controller := &recordingMulticastController{recordingController: &recordingController{}}
	var changes []mib.Change
	protocol, store, _ := newAllowedPreviewEngine(t, controller, mib.ApplyFunc(func(change mib.Change) error {
		changes = append(changes, change)
		return nil
	}))
	sync := store.DataSync()
	changes = nil
	controller.preview = multicast.AllowedPreviewSnapshot{
		MIBDataSync: sync - 1,
		Timers:      []multicast.AllowedPreviewTimer{{RowKey: 7, Duration: 60, TimeLeft: 0}},
	}
	if err := protocol.PollMulticast(); err != nil {
		t.Fatalf("PollMulticast(stale) error = %v", err)
	}
	if len(changes) != 0 || allowedPreviewTableRows(t, store).NumRows != 2 {
		t.Fatal("stale multicast runtime state expired the current MIB row")
	}

	controller.preview.MIBDataSync = sync
	if err := protocol.PollMulticast(); err != nil {
		t.Fatalf("PollMulticast(expired) error = %v", err)
	}
	if store.DataSync() != sync || allowedPreviewTableRows(t, store).NumRows != 0 ||
		len(changes) != 1 || changes[0].Operation != mib.OperationAutonomous ||
		changes[0].MIBDataSync != sync {
		t.Fatalf("allowed-preview expiry state: sync=%d rows=%#v changes=%+v",
			store.DataSync(), allowedPreviewTableRows(t, store), changes)
	}
}

func newAllowedPreviewEngine(t *testing.T, controller Controller,
	applier mib.Applier) (*Engine, *mib.Store, mib.Key) {
	t.Helper()
	store, err := mib.NewWithApplier([]mib.Instance{{
		Key:        mib.Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}, applier)
	if err != nil {
		t.Fatalf("mib.NewWithApplier() error = %v", err)
	}
	key := mib.Key{ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500}
	if err := store.Create(key.ClassID, key.EntityID, me.AttributeValueMap{
		me.MulticastSubscriberConfigInfo_MeType:                            uint8(0),
		me.MulticastSubscriberConfigInfo_MulticastOperationsProfilePointer: uint16(0x700),
	}); err != nil {
		t.Fatalf("Create(multicast subscriber) error = %v", err)
	}
	part0 := make([]byte, 22)
	binary.BigEndian.PutUint16(part0[:2], 1<<14|7)
	copy(part0[14:18], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(part0[18:20], 100)
	binary.BigEndian.PutUint16(part0[20:22], 200)
	part1 := make([]byte, 22)
	binary.BigEndian.PutUint16(part1[:2], 1<<14|1<<11|7)
	copy(part1[14:18], []byte{239, 1, 2, 3})
	binary.BigEndian.PutUint16(part1[18:20], 60)
	if err := store.SetTable(key, multicastSubscriberAllowedPreviewMask, me.AttributeValueMap{
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable: me.TableRows{
			NumRows: 2, Rows: append(part0, part1...),
		},
	}); err != nil {
		t.Fatalf("SetTable(allowed preview) error = %v", err)
	}
	return NewWithController(store, controller), store, key
}

func allowedPreviewTableRows(t *testing.T, store *mib.Store) me.TableRows {
	t.Helper()
	instance, err := store.Get(mib.Key{
		ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: 0x500,
	}, multicastSubscriberAllowedPreviewMask)
	if err != nil {
		t.Fatalf("Get(allowed-preview table) error = %v", err)
	}
	return instance.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable].(me.TableRows)
}

func newMulticastMonitorEngine(t *testing.T, controller Controller, entityID uint16) *Engine {
	t.Helper()
	store, err := mib.New([]mib.Instance{{
		Key: mib.Key{ClassID: me.MulticastSubscriberMonitorClassID, EntityID: entityID},
		Attributes: me.AttributeValueMap{
			me.MulticastSubscriberMonitor_MeType:                    uint8(0),
			me.MulticastSubscriberMonitor_CurrentMulticastBandwidth: uint32(0),
			me.MulticastSubscriberMonitor_JoinMessagesCounter:       uint32(0),
			me.MulticastSubscriberMonitor_BandwidthExceededCounter:  uint32(0),
			me.MulticastSubscriberMonitor_Ipv4ActiveGroupListTable:  me.TableRows{},
			me.MulticastSubscriberMonitor_Ipv6ActiveGroupListTable:  me.TableRows{},
		},
	}})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	return NewWithController(store, controller)
}

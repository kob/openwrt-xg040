// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
)

const notificationUNI = 0x101

func TestAlarmNotificationUpdatesAuditAndSequence(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI}
	var raised [28]byte
	raised[0] = 0x80

	frame, changed, err := protocol.NotifyAlarm(key, raised, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAlarm(raise) error = %v", err)
	}
	if !changed {
		t.Fatal("NotifyAlarm(raise) changed = false, want true")
	}
	alarm := decodeResponse(t, frame).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if alarm.AlarmBitmap != raised || alarm.AlarmSequenceNumber != 1 {
		t.Fatalf("first alarm = %#v, want raised/sequence 1", alarm)
	}

	if frame, changed, err = protocol.NotifyAlarm(key, raised, omci.BaselineIdent); err != nil || changed || frame != nil {
		t.Fatalf("duplicate NotifyAlarm() = frame:%x changed:%v err:%v", frame, changed, err)
	}

	negotiateExtended(t, protocol)
	frame, changed, err = protocol.NotifyAlarm(key, [28]byte{}, omci.ExtendedIdent)
	if err != nil || !changed {
		t.Fatalf("NotifyAlarm(clear) changed=%v error=%v", changed, err)
	}
	alarm = decodeResponse(t, frame).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if alarm.AlarmBitmap != ([28]byte{}) || alarm.AlarmSequenceNumber != 2 || !alarm.Extended {
		t.Fatalf("clear alarm = %#v, want clear/sequence 2/extended", alarm)
	}

	request := encodeRequest(t, 44, omci.GetAllAlarmsRequestType, &omci.GetAllAlarmsRequest{
		MeBasePacket: meBase(me.OnuDataClassID, 0),
	})
	response, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(GetAllAlarms) error = %v", err)
	}
	audit := decodeResponse(t, response).Layer(omci.LayerTypeGetAllAlarmsResponse).(*omci.GetAllAlarmsResponse)
	if audit.NumberOfCommands != 0 {
		t.Fatalf("alarm audit count = %d, want 0 after clear", audit.NumberOfCommands)
	}
}

func TestAlarmNotificationRejectsUndefinedAlarmBit(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	var bitmap [28]byte
	bitmap[0] = 0x40
	_, _, err := protocol.NotifyAlarm(mib.Key{
		ClassID:  me.PhysicalPathTerminationPointEthernetUniClassID,
		EntityID: notificationUNI,
	}, bitmap, omci.BaselineIdent)
	if err == nil {
		t.Fatal("NotifyAlarm(undefined bit) error = nil")
	}
}

func TestONUAdministrativeLockSuppressesNotificationsButRetainsAlarmAudit(t *testing.T) {
	protocol, store := newNotificationEngine(t)
	if err := store.Set(mib.Key{ClassID: me.OnuGClassID, EntityID: 0}, me.AttributeValueMap{
		me.OnuG_AdministrativeState: uint8(1),
	}); err != nil {
		t.Fatalf("lock ONU-G: %v", err)
	}
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI}
	var raised [28]byte
	raised[0] = 0x80
	frame, emitted, err := protocol.NotifyAlarm(key, raised, omci.BaselineIdent)
	if err != nil || emitted || frame != nil {
		t.Fatalf("locked NotifyAlarm() = frame:%x emitted:%v error:%v", frame, emitted, err)
	}
	if protocol.alarmSequence != 0 {
		t.Fatalf("locked alarm sequence = %d, want 0", protocol.alarmSequence)
	}

	request := encodeRequest(t, 0x46, omci.GetAllAlarmsRequestType, &omci.GetAllAlarmsRequest{
		MeBasePacket: meBase(me.OnuDataClassID, 0),
	})
	response, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(GetAllAlarms) error = %v", err)
	}
	audit := decodeResponse(t, response).Layer(omci.LayerTypeGetAllAlarmsResponse).(*omci.GetAllAlarmsResponse)
	if audit.NumberOfCommands != 1 {
		t.Fatalf("locked alarm audit count = %d, want 1", audit.NumberOfCommands)
	}

	frames, err := protocol.NotifyAttributeChange(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
	}, omci.BaselineIdent)
	if err != nil || len(frames) != 0 {
		t.Fatalf("locked AVC frames=%d error=%v", len(frames), err)
	}
	instance, err := store.Get(key, 0x0400)
	if err != nil || instance.Attributes[me.PhysicalPathTerminationPointEthernetUni_OperationalState] != uint8(0) {
		t.Fatalf("locked AVC MIB state = %#v error=%v", instance.Attributes, err)
	}

	if err := store.Set(mib.Key{ClassID: me.OnuGClassID, EntityID: 0}, me.AttributeValueMap{
		me.OnuG_AdministrativeState: uint8(0),
	}); err != nil {
		t.Fatalf("unlock ONU-G: %v", err)
	}
	frame, emitted, err = protocol.NotifyAlarm(key, [28]byte{}, omci.BaselineIdent)
	if err != nil || !emitted || frame == nil {
		t.Fatalf("unlocked NotifyAlarm(clear) = frame:%x emitted:%v error:%v", frame, emitted, err)
	}
	alarm := decodeResponse(t, frame).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if alarm.AlarmSequenceNumber != 1 || alarm.AlarmBitmap != ([28]byte{}) {
		t.Fatalf("unlocked clear alarm = %#v, want sequence 1", alarm)
	}
}

func TestEthernetParentAdministrativeLocksSuppressAlarm(t *testing.T) {
	tests := []struct {
		name      string
		key       mib.Key
		attribute string
	}{
		{name: "circuit pack", key: mib.Key{ClassID: me.CircuitPackClassID, EntityID: 0x0101},
			attribute: me.CircuitPack_AdministrativeState},
		{name: "Ethernet PPTP", key: mib.Key{
			ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI,
		}, attribute: me.PhysicalPathTerminationPointEthernetUni_AdministrativeState},
		{name: "UNI-G", key: mib.Key{ClassID: me.UniGClassID, EntityID: notificationUNI},
			attribute: me.UniG_AdministrativeState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protocol, store := newNotificationEngine(t)
			if err := store.Set(test.key, me.AttributeValueMap{test.attribute: uint8(1)}); err != nil {
				t.Fatalf("lock parent: %v", err)
			}
			var raised [28]byte
			raised[0] = 0x80
			frame, emitted, err := protocol.NotifyAlarm(mib.Key{
				ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI,
			}, raised, omci.BaselineIdent)
			if err != nil || emitted || frame != nil || protocol.alarmSequence != 0 {
				t.Fatalf("locked child alarm = frame:%x emitted:%v sequence:%d error:%v",
					frame, emitted, protocol.alarmSequence, err)
			}
		})
	}
}

func TestAlarmSequenceWrapsAt255(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	protocol.alarmSequence = 255
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI}
	var bitmap [28]byte
	bitmap[0] = 0x80
	first, _, err := protocol.NotifyAlarm(key, bitmap, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAlarm(sequence 255) error = %v", err)
	}
	second, _, err := protocol.NotifyAlarm(key, [28]byte{}, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAlarm(sequence wrap) error = %v", err)
	}
	firstAlarm := decodeResponse(t, first).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	secondAlarm := decodeResponse(t, second).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if firstAlarm.AlarmSequenceNumber != 1 || secondAlarm.AlarmSequenceNumber != 2 {
		t.Fatalf("alarm sequence = %d/%d, want 1/2",
			firstAlarm.AlarmSequenceNumber, secondAlarm.AlarmSequenceNumber)
	}
}

func TestGetAllAlarmsResetsNotificationSequence(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI}
	var bitmap [28]byte
	bitmap[0] = 0x80
	first, _, err := protocol.NotifyAlarm(key, bitmap, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAlarm(first) error = %v", err)
	}
	if sequence := decodeResponse(t, first).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg).AlarmSequenceNumber; sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", sequence)
	}

	request := encodeRequest(t, 45, omci.GetAllAlarmsRequestType, &omci.GetAllAlarmsRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID},
	})
	if _, err := protocol.Handle(request); err != nil {
		t.Fatalf("Handle(GetAllAlarms) error = %v", err)
	}
	clear, _, err := protocol.NotifyAlarm(key, [28]byte{}, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAlarm(clear) error = %v", err)
	}
	if sequence := decodeResponse(t, clear).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg).AlarmSequenceNumber; sequence != 1 {
		t.Fatalf("post-audit sequence = %d, want 1", sequence)
	}
}

func TestAVCUpdatesMIBWithoutDataSync(t *testing.T) {
	protocol, store := newNotificationEngine(t)
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI}
	frames, err := protocol.NotifyAttributeChange(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
	}, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAttributeChange() error = %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("AVC frame count = %d, want 1", len(frames))
	}
	packet := decodeResponse(t, frames[0])
	header := packet.Layer(omci.LayerTypeOMCI).(*omci.OMCI)
	avc := packet.Layer(omci.LayerTypeAttributeValueChange).(*omci.AttributeValueChangeMsg)
	if header.TransactionID != 0 || avc.AttributeMask != 0x0400 ||
		avc.Attributes[me.PhysicalPathTerminationPointEthernetUni_OperationalState] != uint8(0) {
		t.Fatalf("AVC = header:%#v payload:%#v", header, avc)
	}
	if store.DataSync() != 0 {
		t.Fatalf("MIB data sync = %d after AVC, want 0", store.DataSync())
	}

	frames, err = protocol.NotifyAttributeChange(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
	}, omci.BaselineIdent)
	if err != nil || len(frames) != 0 {
		t.Fatalf("duplicate AVC frames=%d err=%v, want 0/nil", len(frames), err)
	}
}

func TestProductionCapabilityRejectsUnadvertisedNotificationsWithoutMutation(t *testing.T) {
	protocol, store, _ := newCapabilityEngine(t)
	key := mib.Key{
		ClassID:  me.PhysicalPathTerminationPointEthernetUniClassID,
		EntityID: notificationUNI,
	}

	before, err := store.Get(key, 0x4200)
	if err != nil {
		t.Fatalf("Get(Ethernet UNI before rejected AVC) error = %v", err)
	}
	frames, err := protocol.NotifyAttributeChange(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd: uint8(0),
	}, omci.BaselineIdent)
	if err == nil || len(frames) != 0 {
		t.Fatalf("unadvertised AVC frames=%d error=%v, want 0/error", len(frames), err)
	}
	after, getErr := store.Get(key, 0x4200)
	if getErr != nil {
		t.Fatalf("Get(Ethernet UNI after rejected AVC) error = %v", getErr)
	}
	if !reflect.DeepEqual(after.Attributes, before.Attributes) {
		t.Fatalf("rejected AVC changed MIB: before=%#v after=%#v", before.Attributes, after.Attributes)
	}

	var bitmap [28]byte
	bitmap[0] = 0x40 // Generated LAN alarm bit 1 is absent from class 288.
	frame, emitted, err := protocol.NotifyAlarm(key, bitmap, omci.BaselineIdent)
	if err == nil || emitted || frame != nil {
		t.Fatalf("unadvertised alarm frame=%x emitted=%t error=%v", frame, emitted, err)
	}
	if _, present := protocol.alarms[key]; present || protocol.alarmSequence != 0 {
		t.Fatalf("rejected alarm changed audit=%t sequence=%d", present, protocol.alarmSequence)
	}

	frames, err = protocol.NotifyAttributeChange(key, me.AttributeValueMap{
		me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(0),
	}, omci.BaselineIdent)
	if err != nil || len(frames) != 1 {
		t.Fatalf("advertised AVC frames=%d error=%v", len(frames), err)
	}
	frame, emitted, err = protocol.NotifyAlarmBit(key, 0, true, omci.BaselineIdent)
	if err != nil || !emitted || frame == nil {
		t.Fatalf("advertised alarm frame=%x emitted=%t error=%v", frame, emitted, err)
	}
}

func TestBaselineAVCSplitsLargeAttributeSet(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	frames, err := protocol.NotifyAttributeChange(mib.Key{
		ClassID: me.SoftwareImageClassID, EntityID: 1,
	}, me.AttributeValueMap{
		me.SoftwareImage_Version:     filled(14, 0x11),
		me.SoftwareImage_ProductCode: filled(25, 0x22),
		me.SoftwareImage_ImageHash:   filled(16, 0x33),
	}, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("NotifyAttributeChange(large) error = %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("baseline AVC frame count = %d, want 3", len(frames))
	}
	var combined uint16
	for _, frame := range frames {
		avc := decodeResponse(t, frame).Layer(omci.LayerTypeAttributeValueChange).(*omci.AttributeValueChangeMsg)
		combined |= avc.AttributeMask
	}
	if combined != 0x8c00 {
		t.Fatalf("combined AVC mask = %#x, want 0x8c00", combined)
	}
}

func TestRequestedTestResultKeepsTCIAndFormat(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	negotiateExtended(t, protocol)
	frame, err := protocol.TestResult(0x1234,
		mib.Key{ClassID: me.OnuGClassID, EntityID: 0}, []byte{1, 2, 3}, omci.ExtendedIdent)
	if err != nil {
		t.Fatalf("TestResult() error = %v", err)
	}
	packet := decodeResponse(t, frame)
	header := packet.Layer(omci.LayerTypeOMCI).(*omci.OMCI)
	result := packet.Layer(omci.LayerTypeTestResult).(*omci.TestResultNotification)
	if header.TransactionID != 0x1234 || header.DeviceIdentifier != omci.ExtendedIdent ||
		len(result.Payload) != 3 || result.Payload[0] != 1 || result.Payload[2] != 3 {
		t.Fatalf("test result = header:%#v payload:%x", header, result.Payload)
	}
}

func TestONUAdministrativeLockSuppressesOnlySelfInitiatedTestResult(t *testing.T) {
	protocol, store := newNotificationEngine(t)
	if err := store.Set(mib.Key{ClassID: me.OnuGClassID, EntityID: 0}, me.AttributeValueMap{
		me.OnuG_AdministrativeState: uint8(1),
	}); err != nil {
		t.Fatalf("lock ONU-G: %v", err)
	}
	key := mib.Key{ClassID: me.OnuGClassID, EntityID: 0}
	frame, err := protocol.TestResult(0, key, []byte{1}, omci.BaselineIdent)
	if err != nil || frame != nil {
		t.Fatalf("self-initiated locked TestResult() = %x, %v", frame, err)
	}
	frame, err = protocol.TestResult(0x1234, key, []byte{1}, omci.BaselineIdent)
	if err != nil || frame == nil {
		t.Fatalf("requested locked TestResult() = %x, %v", frame, err)
	}
	header := decodeResponse(t, frame).Layer(omci.LayerTypeOMCI).(*omci.OMCI)
	if header.TransactionID != 0x1234 {
		t.Fatalf("requested locked TestResult TCI = %#x, want 0x1234", header.TransactionID)
	}
}

func TestExtendedAutonomousMessagesRequireCurrentSessionNegotiation(t *testing.T) {
	protocol, _ := newNotificationEngine(t)
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI}

	frame, changed, err := protocol.NotifyAlarmBit(key, 0, true, omci.ExtendedIdent)
	if err != nil || !changed || omci.DeviceIdent(frame[3]) != omci.BaselineIdent {
		t.Fatalf("pre-negotiation alarm = %x changed=%v error=%v", frame, changed, err)
	}

	negotiateExtended(t, protocol)
	frame, changed, err = protocol.NotifyAlarmBit(key, 0, false, omci.ExtendedIdent)
	if err != nil || !changed || omci.DeviceIdent(frame[3]) != omci.ExtendedIdent {
		t.Fatalf("negotiated alarm = %x changed=%v error=%v", frame, changed, err)
	}

	protocol.ResetCommunicationSession()
	frame, changed, err = protocol.NotifyAlarmBit(key, 0, true, omci.ExtendedIdent)
	if err != nil || !changed || omci.DeviceIdent(frame[3]) != omci.BaselineIdent {
		t.Fatalf("post-reset alarm = %x changed=%v error=%v", frame, changed, err)
	}
	alarm := decodeResponse(t, frame).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if alarm.AlarmSequenceNumber != 1 {
		t.Fatalf("post-reset alarm sequence = %d, want 1", alarm.AlarmSequenceNumber)
	}
}

func negotiateExtended(t *testing.T, protocol *Engine) {
	t.Helper()
	request := encodeRequestForDevice(t, 0x222, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.OnuDataClassID, EntityInstance: 0, Extended: true,
		},
		AttributeMask: 0x8000,
	}, omci.ExtendedIdent)
	if _, err := protocol.Handle(request); err != nil {
		t.Fatalf("negotiate extended message set: %v", err)
	}
}

func newNotificationEngine(t *testing.T) (*Engine, *mib.Store) {
	t.Helper()
	store, err := mib.New([]mib.Instance{
		{
			Key:        mib.Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		{
			Key: mib.Key{ClassID: me.OnuGClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuG_VendorId:            []byte("TEST"),
				me.OnuG_Version:             filled(14, 0),
				me.OnuG_SerialNumber:        filled(8, 0),
				me.OnuG_OperationalState:    uint8(0),
				me.OnuG_AdministrativeState: uint8(0),
			},
		},
		{
			Key: mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: notificationUNI},
			Attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_SensedType:       uint8(0x2f),
				me.PhysicalPathTerminationPointEthernetUni_OperationalState: uint8(1),
			},
		},
		{
			Key: mib.Key{ClassID: me.CircuitPackClassID, EntityID: 0x0101},
			Attributes: me.AttributeValueMap{
				me.CircuitPack_AdministrativeState: uint8(0),
			},
		},
		{
			Key: mib.Key{ClassID: me.UniGClassID, EntityID: notificationUNI},
			Attributes: me.AttributeValueMap{
				me.UniG_AdministrativeState: uint8(0),
			},
		},
		{
			Key: mib.Key{ClassID: me.SoftwareImageClassID, EntityID: 1},
			Attributes: me.AttributeValueMap{
				me.SoftwareImage_Version:     filled(14, 0),
				me.SoftwareImage_IsCommitted: uint8(0),
				me.SoftwareImage_IsActive:    uint8(0),
				me.SoftwareImage_IsValid:     uint8(1),
				me.SoftwareImage_ProductCode: filled(25, 0),
				me.SoftwareImage_ImageHash:   filled(16, 0),
			},
		},
	})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	return New(store), store
}

func meBase(classID me.ClassID, entityID uint16) omci.MeBasePacket {
	return omci.MeBasePacket{EntityClass: classID, EntityInstance: entityID}
}

func filled(size int, value byte) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = value
	}
	return result
}

var _ gopacket.SerializableLayer = (*omci.TestResultNotification)(nil)

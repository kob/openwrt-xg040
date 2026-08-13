// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"testing"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/optical"
	"github.com/xg2010g/airoha-omci/internal/performance"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

func TestRuntimeStatePreservesAlarmAuditAndSequence(t *testing.T) {
	before, store := newNotificationEngine(t)
	key := mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID,
		EntityID: notificationUNI}
	var raised [28]byte
	raised[0] = 0x80
	if _, emitted, err := before.NotifyAlarm(key, raised, omci.BaselineIdent); err != nil || !emitted {
		t.Fatalf("NotifyAlarm() emitted=%t error=%v", emitted, err)
	}
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatalf("ExportRuntimeState() error = %v", err)
	}

	after := New(store)
	if err := after.RestoreRuntimeState(state); err != nil {
		t.Fatalf("RestoreRuntimeState() error = %v", err)
	}
	frame, emitted, err := after.NotifyAlarm(key, [28]byte{}, omci.BaselineIdent)
	if err != nil || !emitted {
		t.Fatalf("post-restart clear emitted=%t error=%v", emitted, err)
	}
	alarm := decodeResponse(t, frame).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if alarm.AlarmSequenceNumber != 2 || alarm.AlarmBitmap != ([28]byte{}) {
		t.Fatalf("post-restart clear = %#v", alarm)
	}
}

func TestRuntimeStatePreservesARCProblemFreeTimer(t *testing.T) {
	before, store := newOpticalEngine(t, 1, 1, 40, 0)
	key := mib.Key{ClassID: me.AniGClassID, EntityID: opticalANI}
	now := time.Date(2026, 8, 12, 4, 0, 0, 0, time.UTC)
	before.now = func() time.Time { return now }
	low := optical.Sample{LaserBiasCurrent: 2500, TransmitPower: 10000, ReceivePower: 10}
	good := optical.Sample{LaserBiasCurrent: 2500, TransmitPower: 10000, ReceivePower: 120}
	if _, err := before.NotifyOpticalSample(key, low, omci.BaselineIdent); err != nil {
		t.Fatal(err)
	}
	if _, err := before.NotifyOpticalSample(key, good, omci.BaselineIdent); err != nil {
		t.Fatal(err)
	}
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}

	after := New(store)
	after.now = func() time.Time { return now }
	if err := after.RestoreRuntimeState(state); err != nil {
		t.Fatalf("RestoreRuntimeState() error = %v", err)
	}
	now = now.Add(59 * time.Second)
	if frames, err := after.PollARC(omci.BaselineIdent); err != nil || len(frames) != 0 {
		t.Fatalf("post-restart PollARC(59s) frames=%d error=%v", len(frames), err)
	}
	now = now.Add(time.Second)
	frames, err := after.PollARC(omci.BaselineIdent)
	if err != nil || len(frames) != 1 {
		t.Fatalf("post-restart PollARC(60s) frames=%d error=%v", len(frames), err)
	}
}

func TestRuntimeStatePreservesBERSampleForThresholdReevaluation(t *testing.T) {
	before, store := newOpticalEngine(t, 0, 0, 0xff, 0xff)
	key := mib.Key{ClassID: me.AniGClassID, EntityID: opticalANI}
	sample := BERSample{Sequence: 7, BIPCount: 3, IntervalMS: 1000, BootID: testBootID}
	if frames, err := before.NotifyBERSample(key, sample, omci.BaselineIdent); err != nil || len(frames) != 1 {
		t.Fatalf("NotifyBERSample() frames=%d error=%v", len(frames), err)
	}
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.BERSamples) != 1 || state.BERSamples[0].Sample != sample {
		t.Fatalf("exported BER samples = %#v", state.BERSamples)
	}

	after := New(store)
	if err := after.RestoreRuntimeState(state); err != nil {
		t.Fatalf("RestoreRuntimeState() error = %v", err)
	}
	if _, err := after.NotifyBERSample(key, sample, omci.BaselineIdent); err == nil ||
		!strings.Contains(err.Error(), "not newer") {
		t.Fatalf("restored duplicate BER sequence error = %v", err)
	}

	request := encodeRequest(t, 111, omci.SetRequestType, &omci.SetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass: me.AniGClassID, EntityInstance: opticalANI,
		},
		AttributeMask: 0x0200,
		Attributes: me.AttributeValueMap{
			me.AniG_SignalDegradeThreshold: uint8(8),
		},
	})
	response, err := after.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Set SD threshold) error = %v", err)
	}
	if result := decodeResponse(t, response).Layer(omci.LayerTypeSetResponse).(*omci.SetResponse).Result; result != me.Success {
		t.Fatalf("Set SD threshold result = %v", result)
	}
	frames := after.DrainNotifications()
	if len(frames) != 1 {
		t.Fatalf("post-restart threshold notifications = %d, want one clear", len(frames))
	}
	alarm := decodeResponse(t, frames[0]).Layer(omci.LayerTypeAlarmNotification).(*omci.AlarmNotificationMsg)
	if alarm.AlarmBitmap != ([28]byte{}) {
		t.Fatalf("post-restart threshold bitmap = %x, want clear", alarm.AlarmBitmap)
	}
}

func TestRuntimeStateRejectsInvalidBERSamplesWithoutPartialRestore(t *testing.T) {
	before, _ := newOpticalEngine(t, 0, 0, 0xff, 0xff)
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}
	aniKey := mib.Key{ClassID: me.AniGClassID, EntityID: opticalANI}
	valid := RuntimeBERSample{Key: aniKey, Sample: BERSample{
		Sequence: 1, BIPCount: 1, IntervalMS: 1000, BootID: testBootID,
	}}
	tests := map[string][]RuntimeBERSample{
		"wrong class":     {{Key: mib.Key{ClassID: me.OnuGClassID}, Sample: valid.Sample}},
		"missing ANI":     {{Key: mib.Key{ClassID: me.AniGClassID, EntityID: opticalANI + 1}, Sample: valid.Sample}},
		"zero sequence":   {{Key: aniKey, Sample: BERSample{IntervalMS: 1000, BootID: testBootID}}},
		"zero interval":   {{Key: aniKey, Sample: BERSample{Sequence: 1, BootID: testBootID}}},
		"invalid boot ID": {{Key: aniKey, Sample: BERSample{Sequence: 1, IntervalMS: 1000, BootID: "invalid"}}},
		"duplicate":       {valid, valid},
	}
	for name, samples := range tests {
		t.Run(name, func(t *testing.T) {
			after := New(before.mib)
			sentinelKey := mib.Key{ClassID: me.AniGClassID, EntityID: 0xffff}
			after.berSample[sentinelKey] = BERSample{Sequence: 9, IntervalMS: 1, BootID: testBootID}
			invalid := state
			invalid.BERSamples = samples
			if err := after.RestoreRuntimeState(invalid); err == nil {
				t.Fatal("RestoreRuntimeState(invalid BER sample) error = nil")
			}
			if len(after.berSample) != 1 || after.berSample[sentinelKey].Sequence != 9 {
				t.Fatalf("failed restore partially changed BER samples: %#v", after.berSample)
			}
		})
	}
}

func TestRuntimeStatePreservesPerformanceHistoryBaselineAndTCA(t *testing.T) {
	before, store, controller := newEthernetPerformanceEngine(t, false)
	now := time.Date(2026, 8, 12, 5, 0, 0, 0, time.UTC)
	before.now = func() time.Time { return now }
	thresholdID := uint16(0x950)
	if err := store.Create(me.ThresholdData1ClassID, thresholdID, me.AttributeValueMap{
		me.ThresholdData1_ThresholdValue1: uint32(5),
	}); err != nil {
		t.Fatal(err)
	}
	controller.ethernetCounters.Received.DropEvents = 100
	createEthernetPerformanceWithThreshold(t, before,
		me.EthernetPerformanceMonitoringHistoryData3ClassID,
		testGEMEntity, thresholdID, 0x780)
	pollPerformance(t, before)
	controller.ethernetCounters.Received.DropEvents = 105
	if frames := pollPerformance(t, before); len(frames) != 1 {
		t.Fatalf("initial TCA frames = %d", len(frames))
	}

	now = now.Add(performanceInterval)
	controller.ethernetCounters.Received.DropEvents = 110
	if frames := pollPerformance(t, before); len(frames) != 1 {
		t.Fatalf("first interval clear frames = %d", len(frames))
	}
	controller.ethernetCounters.Received.DropEvents = 115
	if frames := pollPerformance(t, before); len(frames) != 1 {
		t.Fatalf("second interval TCA frames = %d", len(frames))
	}
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatalf("ExportRuntimeState() error = %v", err)
	}
	key := mib.Key{ClassID: me.EthernetPerformanceMonitoringHistoryData3ClassID,
		EntityID: testGEMEntity}
	if _, err := store.UpdateAutonomous(key, me.AttributeValueMap{
		me.EthernetPerformanceMonitoringHistoryData3_IntervalEndTime: uint8(0),
		me.EthernetPerformanceMonitoringHistoryData3_DropEvents:      uint32(0),
	}); err != nil {
		t.Fatal(err)
	}

	after := New(store)
	after.SetPerformanceController(controller)
	after.now = func() time.Time { return now }
	if err := after.RestoreRuntimeState(state); err != nil {
		t.Fatalf("RestoreRuntimeState() error = %v", err)
	}
	history, err := store.Get(key, 0xa000)
	if err != nil ||
		history.Attributes[me.EthernetPerformanceMonitoringHistoryData3_IntervalEndTime] != uint8(1) ||
		history.Attributes[me.EthernetPerformanceMonitoringHistoryData3_DropEvents] != uint32(10) {
		t.Fatalf("restored PM history = %#v error=%v", history.Attributes, err)
	}
	current := getCurrentPerformance(t, after,
		me.EthernetPerformanceMonitoringHistoryData3ClassID,
		testGEMEntity, 0x2000, 0x781)
	if current.Attributes[me.EthernetPerformanceMonitoringHistoryData3_DropEvents] != uint32(5) {
		t.Fatalf("restored current PM = %#v", current.Attributes)
	}
	if frames := pollPerformance(t, after); len(frames) != 0 {
		t.Fatalf("restored active TCA repeated in %d frames", len(frames))
	}

	now = now.Add(performanceInterval)
	controller.ethernetCounters.Received.DropEvents = 120
	frames := pollPerformance(t, after)
	if len(frames) != 1 {
		t.Fatalf("post-restart interval clear frames = %d", len(frames))
	}
	history, err = store.Get(key, 0x2000)
	if err != nil ||
		history.Attributes[me.EthernetPerformanceMonitoringHistoryData3_DropEvents] != uint32(10) {
		t.Fatalf("post-restart PM history = %#v error=%v", history.Attributes, err)
	}
}

func TestRuntimeStateRejectsCounterResetWithoutPartialRestore(t *testing.T) {
	before, store, controller := newPerformanceEngine(t)
	now := time.Date(2026, 8, 12, 6, 0, 0, 0, time.UTC)
	before.now = func() time.Time { return now }
	controller.counters = performance.GEMPortCounters{ReceivedGEMFrames: 100}
	pollPerformance(t, before)
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}
	controller.counters = performance.GEMPortCounters{ReceivedGEMFrames: 10}
	after := New(store)
	after.SetPerformanceController(controller)
	var alarm [28]byte
	alarm[0] = 0x80
	after.alarms[mib.Key{ClassID: me.GemPortNetworkCtpClassID,
		EntityID: testGEMEntity}] = alarm
	err = after.RestoreRuntimeState(state)
	if err == nil || !strings.Contains(err.Error(), "reset below") {
		t.Fatalf("RestoreRuntimeState(counter reset) error = %v", err)
	}
	if len(after.alarms) != 1 || !after.performanceNext.IsZero() {
		t.Fatalf("failed restore partially changed engine: alarms=%d next=%v",
			len(after.alarms), after.performanceNext)
	}
}

func TestRuntimeStatePreservesXGSPONPerformanceHistoriesAndBaselines(t *testing.T) {
	baseline := performance.XGSPONCounters{
		TC: performance.XGSPONTCCounters{
			PSBdHECErrors: 100, TransmittedNonIdleBytes: 1000,
		},
		Downstream: performance.XGSPONDownstreamManagementCounters{
			PLOAMMICErrors: 200, BaselineOMCIMessages: 2000,
		},
		Upstream: performance.XGSPONUpstreamManagementCounters{
			RegistrationMessages: 300,
		},
	}
	before, store, controller := newXGSPerformanceEngine(t, baseline)
	now := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)
	before.now = func() time.Time { return now }
	pollPerformance(t, before)
	controller.xgsCounters.TC.PSBdHECErrors += 10
	controller.xgsCounters.TC.TransmittedNonIdleBytes += 100
	controller.xgsCounters.Downstream.PLOAMMICErrors += 20
	controller.xgsCounters.Downstream.BaselineOMCIMessages += 200
	controller.xgsCounters.Upstream.RegistrationMessages += 30
	now = now.Add(performanceInterval)
	pollPerformance(t, before)

	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatalf("ExportRuntimeState() error = %v", err)
	}
	if len(state.XGSPerformance) != len(xgsPerformanceClasses()) {
		t.Fatalf("exported XGS-PON performance entries = %d, want %d",
			len(state.XGSPerformance), len(xgsPerformanceClasses()))
	}
	controller.xgsCounters.TC.PSBdHECErrors += 1
	controller.xgsCounters.Downstream.PLOAMMICErrors += 2
	controller.xgsCounters.Upstream.RegistrationMessages += 3
	for _, classID := range xgsPerformanceClasses() {
		key := mib.Key{ClassID: classID, EntityID: testANIEntity}
		if _, err := store.UpdateAutonomous(key, xgsPerformanceAttributes(
			classID, 0, performance.XGSPONCounters{})); err != nil {
			t.Fatalf("clear XGS-PON history class %v: %v", classID, err)
		}
	}

	after := NewForMode(store, controller, nil, pon.XGSPON)
	after.now = func() time.Time { return now }
	if err := after.RestoreRuntimeState(state); err != nil {
		t.Fatalf("RestoreRuntimeState() error = %v", err)
	}
	checks := []struct {
		classID     me.ClassID
		mask        uint16
		name        string
		historyWant interface{}
		currentWant interface{}
	}{
		{me.XgPonTcPerformanceMonitoringHistoryDataClassID, 0x2000,
			me.XgPonTcPerformanceMonitoringHistoryData_PsbdHecErrorCount, uint32(10), uint32(1)},
		{me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID, 0x2000,
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_PloamMessageIntegrityCheckMicErrorCount,
			uint32(20), uint32(2)},
		{me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID, 0x0800,
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_RegistrationMessageCount,
			uint32(30), uint32(3)},
	}
	for index, check := range checks {
		key := mib.Key{ClassID: check.classID, EntityID: testANIEntity}
		history, err := store.Get(key, 0x8000|check.mask)
		if err != nil || history.Attributes[check.name] != check.historyWant ||
			history.Attributes[me.XgPonTcPerformanceMonitoringHistoryData_IntervalEndTime] != uint8(1) {
			t.Fatalf("restored XGS-PON history class %v = %#v error=%v",
				check.classID, history.Attributes, err)
		}
		current := getCurrentXGSPerformance(t, after, check.classID, testANIEntity,
			check.mask, uint16(0x790+index))
		if current.Attributes[check.name] != check.currentWant {
			t.Fatalf("restored XGS-PON current class %v = %#v, want %v",
				check.classID, current.Attributes[check.name], check.currentWant)
		}
	}
}

func TestRuntimeStateRejectsXGSPONCounterResetWithoutPartialRestore(t *testing.T) {
	baseline := performance.XGSPONCounters{
		TC: performance.XGSPONTCCounters{XGEMKeyErrors: 100},
	}
	before, store, controller := newXGSPerformanceEngine(t, baseline)
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}
	controller.xgsCounters.TC.XGEMKeyErrors = 99
	after := NewForMode(store, controller, nil, pon.XGSPON)
	var alarm [28]byte
	alarm[0] = 0x80
	sentinel := mib.Key{ClassID: me.AniGClassID, EntityID: testANIEntity}
	after.alarms[sentinel] = alarm
	err = after.RestoreRuntimeState(state)
	if err == nil || !strings.Contains(err.Error(), "reset below") {
		t.Fatalf("RestoreRuntimeState(XGS-PON counter reset) error = %v", err)
	}
	if len(after.alarms) != 1 || after.alarms[sentinel] != alarm || len(after.xgsPMState) != 0 {
		t.Fatalf("failed XGS-PON restore partially changed engine: alarms=%#v PM=%#v",
			after.alarms, after.xgsPMState)
	}
}

func TestRuntimeStateRejectsDifferentMIB(t *testing.T) {
	before, store := newNotificationEngine(t)
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(mib.Key{ClassID: me.OnuGClassID}, me.AttributeValueMap{
		me.OnuG_AdministrativeState: uint8(1),
	}); err != nil {
		t.Fatal(err)
	}
	err = New(store).RestoreRuntimeState(state)
	if err == nil || (!strings.Contains(err.Error(), "data sync") &&
		!strings.Contains(err.Error(), "fingerprint")) {
		t.Fatalf("RestoreRuntimeState(different MIB) error = %v", err)
	}
}

func TestRuntimeStateRejectsDifferentPONMode(t *testing.T) {
	before, store := newNotificationEngine(t)
	state, err := before.ExportRuntimeState()
	if err != nil {
		t.Fatal(err)
	}
	after := NewForMode(store, nil, nil, pon.XGSPON)
	err = after.RestoreRuntimeState(state)
	if err == nil || !strings.Contains(err.Error(), "PON mode") {
		t.Fatalf("RestoreRuntimeState(cross-mode) error = %v", err)
	}
}

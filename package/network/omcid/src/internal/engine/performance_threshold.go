// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"sort"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
)

const performanceThresholdAttribute = me.GemPortNetworkCtpPerformanceMonitoringHistoryData_ThresholdData12Id

var performanceThresholdValueNames = [...]string{
	"",
	me.ThresholdData1_ThresholdValue1,
	me.ThresholdData1_ThresholdValue2,
	me.ThresholdData1_ThresholdValue3,
	me.ThresholdData1_ThresholdValue4,
	me.ThresholdData1_ThresholdValue5,
	me.ThresholdData1_ThresholdValue6,
	me.ThresholdData1_ThresholdValue7,
	me.ThresholdData2_ThresholdValue8,
	me.ThresholdData2_ThresholdValue9,
	me.ThresholdData2_ThresholdValue10,
	me.ThresholdData2_ThresholdValue11,
	me.ThresholdData2_ThresholdValue12,
	me.ThresholdData2_ThresholdValue13,
	me.ThresholdData2_ThresholdValue14,
}

type performanceThresholdRule struct {
	counter       string
	threshold     uint8
	thresholdName string
	value         uint32
	alarm         uint8
}

func isPerformanceClass(classID me.ClassID) bool {
	return classID == me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID ||
		classID == me.FecPerformanceMonitoringHistoryDataClassID ||
		isEthernetPerformanceClass(classID) || isXGSPONPerformanceClass(classID)
}

func performanceThresholdRules(classID me.ClassID) []performanceThresholdRule {
	switch classID {
	case me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID:
		// XG2010G does not expose a GEM encryption-error counter or TCA.
		return nil
	case me.XgPonTcPerformanceMonitoringHistoryDataClassID:
		return []performanceThresholdRule{
			{counter: me.XgPonTcPerformanceMonitoringHistoryData_PsbdHecErrorCount, threshold: 1, alarm: 1},
			{counter: me.XgPonTcPerformanceMonitoringHistoryData_XgtcHecErrorCount, threshold: 2, alarm: 2},
			{counter: me.XgPonTcPerformanceMonitoringHistoryData_UnknownProfileCount, threshold: 3, alarm: 3},
			{counter: me.XgPonTcPerformanceMonitoringHistoryData_XgemHecLostWordsCount, threshold: 4, alarm: 4},
			{counter: me.XgPonTcPerformanceMonitoringHistoryData_XgemKeyErrors, threshold: 5, alarm: 5},
			{counter: me.XgPonTcPerformanceMonitoringHistoryData_XgemHecErrorCount, threshold: 6, alarm: 6},
		}
	case me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID:
		return []performanceThresholdRule{
			{counter: me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_PloamMessageIntegrityCheckMicErrorCount, threshold: 1, alarm: 1},
			{counter: me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_OmciMicErrorCount, threshold: 2, alarm: 2},
		}
	case me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID:
		return nil
	case me.FecPerformanceMonitoringHistoryDataClassID:
		return []performanceThresholdRule{
			{counter: me.FecPerformanceMonitoringHistoryData_CorrectedBytes, threshold: 1, alarm: 0},
			{counter: me.FecPerformanceMonitoringHistoryData_CorrectedCodeWords, threshold: 2, alarm: 1},
			{counter: me.FecPerformanceMonitoringHistoryData_UncorrectableCodeWords, threshold: 3, alarm: 2},
			{counter: me.FecPerformanceMonitoringHistoryData_FecSeconds, threshold: 4, alarm: 4},
		}
	case me.EthernetPerformanceMonitoringHistoryDataClassID:
		counters := []string{
			me.EthernetPerformanceMonitoringHistoryData_FcsErrors,
			me.EthernetPerformanceMonitoringHistoryData_ExcessiveCollisionCounter,
			me.EthernetPerformanceMonitoringHistoryData_LateCollisionCounter,
			me.EthernetPerformanceMonitoringHistoryData_FramesTooLong,
			me.EthernetPerformanceMonitoringHistoryData_BufferOverflowsOnReceive,
			me.EthernetPerformanceMonitoringHistoryData_BufferOverflowsOnTransmit,
			me.EthernetPerformanceMonitoringHistoryData_SingleCollisionFrameCounter,
			me.EthernetPerformanceMonitoringHistoryData_MultipleCollisionsFrameCounter,
			me.EthernetPerformanceMonitoringHistoryData_SqeCounter,
			me.EthernetPerformanceMonitoringHistoryData_DeferredTransmissionCounter,
			me.EthernetPerformanceMonitoringHistoryData_InternalMacTransmitErrorCounter,
			me.EthernetPerformanceMonitoringHistoryData_CarrierSenseErrorCounter,
			me.EthernetPerformanceMonitoringHistoryData_AlignmentErrorCounter,
			me.EthernetPerformanceMonitoringHistoryData_InternalMacReceiveErrorCounter,
		}
		return sequentialPerformanceThresholdRules(counters)
	case me.EthernetPerformanceMonitoringHistoryData3ClassID:
		return []performanceThresholdRule{
			{counter: me.EthernetPerformanceMonitoringHistoryData3_DropEvents, threshold: 1, alarm: 0},
			{counter: me.EthernetPerformanceMonitoringHistoryData3_UndersizePackets, threshold: 2, alarm: 1},
			{counter: me.EthernetPerformanceMonitoringHistoryData3_Fragments, threshold: 3, alarm: 2},
			{counter: me.EthernetPerformanceMonitoringHistoryData3_Jabbers, threshold: 4, alarm: 3},
		}
	case me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID:
		return []performanceThresholdRule{
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataDownstream_DropEvents, threshold: 1, alarm: 0},
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataDownstream_CrcErroredPackets, threshold: 2, alarm: 1},
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataDownstream_UndersizePackets, threshold: 3, alarm: 2},
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataDownstream_OversizePackets, threshold: 4, alarm: 3},
		}
	case me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID:
		return []performanceThresholdRule{
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataUpstream_DropEvents, threshold: 1, alarm: 0},
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataUpstream_CrcErroredPackets, threshold: 2, alarm: 1},
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataUpstream_UndersizePackets, threshold: 3, alarm: 2},
			{counter: me.EthernetFramePerformanceMonitoringHistoryDataUpstream_OversizePackets, threshold: 4, alarm: 3},
		}
	default:
		return nil
	}
}

func sequentialPerformanceThresholdRules(counters []string) []performanceThresholdRule {
	rules := make([]performanceThresholdRule, len(counters))
	for index, counter := range counters {
		rules[index] = performanceThresholdRule{
			counter: counter, threshold: uint8(index + 1), alarm: uint8(index),
		}
	}
	return rules
}

func (e *Engine) validatePerformanceThresholdPointerLocked(classID me.ClassID,
	attributes me.AttributeValueMap) error {
	if !isPerformanceClass(classID) {
		return nil
	}
	value, present := attributes[performanceThresholdAttribute]
	if !present {
		return nil
	}
	thresholdID, ok := value.(uint16)
	if !ok {
		return &mib.ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("performance threshold pointer has invalid type %T", value)}
	}
	if thresholdID != 0 && !e.mib.Exists(mib.Key{
		ClassID: me.ThresholdData1ClassID, EntityID: thresholdID,
	}) {
		return &mib.ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("performance threshold data 1 %#x does not exist", thresholdID)}
	}
	return nil
}

func (e *Engine) performanceThresholdReferencedLocked(thresholdID uint16) bool {
	for _, instance := range e.mib.Snapshot() {
		if !isPerformanceClass(instance.ClassID) {
			continue
		}
		if value, ok := instance.Attributes[performanceThresholdAttribute].(uint16); ok && value == thresholdID {
			return true
		}
	}
	return false
}

func (e *Engine) performanceThresholdsLocked(key mib.Key) ([]performanceThresholdRule, error) {
	instance, err := e.mib.Get(key, 0x4000)
	if err != nil {
		return nil, err
	}
	thresholdID, ok := instance.Attributes[performanceThresholdAttribute].(uint16)
	if !ok {
		return nil, fmt.Errorf("performance threshold pointer is missing from %v/%#x",
			key.ClassID, key.EntityID)
	}
	if thresholdID == 0 {
		return nil, nil
	}

	threshold1, err := e.mib.Get(mib.Key{
		ClassID: me.ThresholdData1ClassID, EntityID: thresholdID,
	}, 0xfe00)
	if err != nil {
		return nil, fmt.Errorf("resolve threshold data 1 %#x: %w", thresholdID, err)
	}
	threshold2, threshold2Err := e.mib.Get(mib.Key{
		ClassID: me.ThresholdData2ClassID, EntityID: thresholdID,
	}, 0xfe00)
	if threshold2Err != nil && e.mib.Exists(mib.Key{
		ClassID: me.ThresholdData2ClassID, EntityID: thresholdID,
	}) {
		return nil, fmt.Errorf("resolve threshold data 2 %#x: %w", thresholdID, threshold2Err)
	}

	configured := make([]performanceThresholdRule, 0)
	for _, rule := range performanceThresholdRules(key.ClassID) {
		var attributes me.AttributeValueMap
		if rule.threshold <= 7 {
			attributes = threshold1.Attributes
		} else if threshold2Err == nil {
			attributes = threshold2.Attributes
		} else {
			continue
		}
		rule.thresholdName = performanceThresholdValueNames[rule.threshold]
		raw, present := attributes[rule.thresholdName]
		if !present {
			continue
		}
		value, ok := raw.(uint32)
		if !ok {
			return nil, fmt.Errorf("threshold data %#x %s has invalid type %T",
				thresholdID, rule.thresholdName, raw)
		}
		if value != 0 && value != 0xffff {
			rule.value = value
			configured = append(configured, rule)
		}
	}
	return configured, nil
}

func (e *Engine) evaluatePerformanceTCALocked(key mib.Key,
	attributes me.AttributeValueMap, rules []performanceThresholdRule,
	device omci.DeviceIdent) ([]byte, bool, error) {
	if len(rules) == 0 {
		return nil, false, nil
	}
	bitmap := e.performanceTCA[key]
	changed := false
	for _, rule := range rules {
		counter, ok := performanceCounterValue(attributes[rule.counter])
		if !ok {
			return nil, false, fmt.Errorf("performance counter %s has invalid type %T",
				rule.counter, attributes[rule.counter])
		}
		octet := rule.alarm / 8
		bit := uint(7 - rule.alarm%8)
		if counter >= uint64(rule.value) && bitmap[octet]&(1<<bit) == 0 {
			bitmap[octet] |= 1 << bit
			changed = true
		}
	}
	if !changed {
		return nil, false, nil
	}
	frame, emitted, err := e.notifyAlarmLocked(key, bitmap, device)
	if err != nil {
		return nil, false, err
	}
	if emitted {
		e.performanceTCA[key] = bitmap
	}
	return frame, emitted, nil
}

func performanceCounterValue(value interface{}) (uint64, bool) {
	switch counter := value.(type) {
	case uint8:
		return uint64(counter), true
	case uint16:
		return uint64(counter), true
	case uint32:
		return uint64(counter), true
	case uint64:
		return counter, true
	default:
		return 0, false
	}
}

func (e *Engine) clearPerformanceTCAKeyLocked(key mib.Key) {
	if _, present := e.performanceTCA[key]; !present {
		return
	}
	delete(e.performanceTCA, key)
	delete(e.alarms, key)
}

func (e *Engine) clearAllPerformanceTCAsLocked() {
	for key := range e.performanceTCA {
		delete(e.alarms, key)
	}
	e.performanceTCA = make(map[mib.Key][28]byte)
}

func (e *Engine) clearPerformanceTCANotificationsLocked(
	device omci.DeviceIdent) ([][]byte, error) {
	keys := make([]mib.Key, 0, len(e.performanceTCA))
	for key := range e.performanceTCA {
		keys = append(keys, key)
	}
	sortMIBKeys(keys)

	frames := make([][]byte, 0, len(keys))
	for _, key := range keys {
		frame, emitted, err := e.notifyAlarmLocked(key, [28]byte{}, device)
		if err != nil {
			return frames, fmt.Errorf("clear performance TCA for %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		if emitted {
			frames = append(frames, frame)
		}
		delete(e.performanceTCA, key)
	}
	return frames, nil
}

func sortMIBKeys(keys []mib.Key) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ClassID == keys[j].ClassID {
			return keys[i].EntityID < keys[j].EntityID
		}
		return keys[i].ClassID < keys[j].ClassID
	})
}

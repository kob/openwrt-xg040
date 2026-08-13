// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"math"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/performance"
)

const performanceInterval = 15 * time.Minute

type performanceState struct {
	portID   uint16
	baseline performance.GEMPortCounters
}

type ethernetPerformanceState struct {
	uniEntityID uint16
	baseline    performance.EthernetCounters
}

type fecPerformanceState struct {
	aniEntityID uint16
	baseline    performance.FECCounters
}

type xgsPerformanceState struct {
	aniEntityID uint16
	baseline    performance.XGSPONCounters
}

type performanceSynchronization struct {
	gem      map[mib.Key]performance.GEMPortCounters
	fec      map[mib.Key]performance.FECCounters
	ethernet map[mib.Key]performance.EthernetCounters
	xgs      map[mib.Key]performance.XGSPONCounters
}

func isEthernetPerformanceClass(classID me.ClassID) bool {
	switch classID {
	case me.EthernetPerformanceMonitoringHistoryDataClassID,
		me.EthernetPerformanceMonitoringHistoryData3ClassID,
		me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID,
		me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID:
		return true
	default:
		return false
	}
}

func isXGSPONPerformanceClass(classID me.ClassID) bool {
	switch classID {
	case me.XgPonTcPerformanceMonitoringHistoryDataClassID,
		me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID,
		me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID:
		return true
	default:
		return false
	}
}

func (e *Engine) prepareXGSPerformanceCreateLocked(classID me.ClassID,
	entityID uint16) (*xgsPerformanceState, error) {
	key := mib.Key{ClassID: classID, EntityID: entityID}
	if e.mib.Exists(key) {
		return nil, nil
	}
	if e.xgsPerformance == nil {
		return nil, &mib.ResultError{Result: me.NotSupported}
	}
	if !e.mib.Exists(mib.Key{ClassID: me.AniGClassID, EntityID: entityID}) {
		return nil, &mib.ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("XGS-PON PM references missing ANI-G %#x", entityID)}
	}
	baseline, err := e.xgsPerformance.XGSPONCounters(entityID)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ProcessingError, Cause: err}
	}
	return &xgsPerformanceState{aniEntityID: entityID, baseline: baseline}, nil
}

func (e *Engine) resolveEthernetPerformanceUNILocked(key mib.Key) (uint16, error) {
	uniEntityID := key.EntityID
	switch key.ClassID {
	case me.EthernetPerformanceMonitoringHistoryDataClassID,
		me.EthernetPerformanceMonitoringHistoryData3ClassID:
	case me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID,
		me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID:
		bridgePort, err := e.mib.Get(mib.Key{
			ClassID: me.MacBridgePortConfigurationDataClassID, EntityID: key.EntityID,
		}, 0x3000)
		if err != nil {
			return 0, fmt.Errorf("Ethernet frame PM parent: %w", err)
		}
		tpType, ok := bridgePort.Attributes[me.MacBridgePortConfigurationData_TpType].(uint8)
		if !ok || tpType != 1 {
			return 0, fmt.Errorf("Ethernet frame PM requires a PPTP Ethernet UNI bridge port")
		}
		var present bool
		uniEntityID, present = bridgePort.Attributes[me.MacBridgePortConfigurationData_TpPointer].(uint16)
		if !present {
			return 0, fmt.Errorf("Ethernet frame PM parent has an invalid TP pointer")
		}
	default:
		return 0, fmt.Errorf("unsupported Ethernet performance class %v", key.ClassID)
	}
	if !e.mib.Exists(mib.Key{
		ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: uniEntityID,
	}) {
		return 0, fmt.Errorf("Ethernet PM references missing PPTP Ethernet UNI %#x", uniEntityID)
	}
	return uniEntityID, nil
}

func (e *Engine) prepareEthernetPerformanceCreateLocked(classID me.ClassID,
	entityID uint16) (*ethernetPerformanceState, error) {
	key := mib.Key{ClassID: classID, EntityID: entityID}
	if e.mib.Exists(key) {
		return nil, nil
	}
	if e.ethernetPerformance == nil {
		return nil, &mib.ResultError{Result: me.NotSupported}
	}
	uniEntityID, err := e.resolveEthernetPerformanceUNILocked(key)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ParameterError, Cause: err}
	}
	baseline, err := e.ethernetPerformance.EthernetCounters(uniEntityID)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ProcessingError, Cause: err}
	}
	return &ethernetPerformanceState{uniEntityID: uniEntityID, baseline: baseline}, nil
}

func (e *Engine) bridgePortHasPerformanceLocked(entityID uint16) bool {
	return e.mib.Exists(mib.Key{
		ClassID:  me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID,
		EntityID: entityID,
	}) || e.mib.Exists(mib.Key{
		ClassID:  me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID,
		EntityID: entityID,
	})
}

func bridgePortAssociationChanged(attributes me.AttributeValueMap) bool {
	_, typeChanged := attributes[me.MacBridgePortConfigurationData_TpType]
	_, pointerChanged := attributes[me.MacBridgePortConfigurationData_TpPointer]
	return typeChanged || pointerChanged
}

func (e *Engine) prepareGEMPerformanceCreateLocked(entityID uint16) (*performanceState, error) {
	key := mib.Key{
		ClassID:  me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID,
		EntityID: entityID,
	}
	if e.mib.Exists(key) {
		return nil, nil
	}
	if e.performance == nil {
		return nil, &mib.ResultError{Result: me.NotSupported}
	}
	parent, err := e.mib.Get(mib.Key{
		ClassID: me.GemPortNetworkCtpClassID, EntityID: entityID,
	}, 0x8000)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ParameterError, Cause: fmt.Errorf("GEM PM parent: %w", err)}
	}
	portID, ok := parent.Attributes[me.GemPortNetworkCtp_PortId].(uint16)
	if !ok || portID > 0x0fff {
		return nil, &mib.ResultError{Result: me.ParameterError, Cause: fmt.Errorf("GEM PM parent has invalid port ID")}
	}
	baseline, err := e.performance.GEMPortCounters(portID)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ProcessingError, Cause: err}
	}
	return &performanceState{portID: portID, baseline: baseline}, nil
}

func (e *Engine) prepareFECPerformanceCreateLocked(entityID uint16) (*fecPerformanceState, error) {
	key := mib.Key{ClassID: me.FecPerformanceMonitoringHistoryDataClassID, EntityID: entityID}
	if e.mib.Exists(key) {
		return nil, nil
	}
	if e.fecPerformance == nil {
		return nil, &mib.ResultError{Result: me.NotSupported}
	}
	if !e.mib.Exists(mib.Key{ClassID: me.AniGClassID, EntityID: entityID}) {
		return nil, &mib.ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("FEC PM references missing ANI-G %#x", entityID)}
	}
	baseline, err := e.fecPerformance.FECCounters(entityID)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ProcessingError, Cause: err}
	}
	return &fecPerformanceState{aniEntityID: entityID, baseline: baseline}, nil
}

// SetPerformanceController installs the platform counter source. It is mainly
// useful to embedders that do not use the combined platform controller.
func (e *Engine) SetPerformanceController(controller performance.Controller) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.performance = controller
	e.performanceState = make(map[mib.Key]performanceState)
	e.fecPerformance, _ = controller.(performance.FECController)
	e.fecPMState = make(map[mib.Key]fecPerformanceState)
	e.ethernetPerformance, _ = controller.(performance.EthernetController)
	e.ethernetPMState = make(map[mib.Key]ethernetPerformanceState)
	e.xgsPerformance, _ = controller.(performance.XGSPONController)
	e.xgsPMState = make(map[mib.Key]xgsPerformanceState)
	e.clearAllPerformanceTCAsLocked()
	e.performanceNext = time.Time{}
	e.performanceIntervalEnd = 0
}

// PollPerformance advances completed 15-minute collection intervals and
// returns threshold crossing alerts raised since the previous poll. Hardware
// is sampled inside an interval only while at least one enabled threshold is
// configured for that PM instance.
func (e *Engine) PollPerformance(device omci.DeviceIdent) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := validateDeviceIdentifier(device); err != nil {
		return nil, err
	}
	return e.pollPerformanceLocked(e.now(), e.notificationDeviceLocked(device))
}

type performanceThresholdEvaluation struct {
	attributes me.AttributeValueMap
	rules      []performanceThresholdRule
}

func (e *Engine) pollPerformanceLocked(now time.Time,
	device omci.DeviceIdent) ([][]byte, error) {
	if e.performance == nil && e.fecPerformance == nil && e.ethernetPerformance == nil &&
		e.xgsPerformance == nil {
		return nil, nil
	}
	if err := e.reconcilePerformanceLocked(); err != nil {
		return nil, err
	}
	if e.performanceNext.IsZero() {
		e.performanceNext = now.Add(performanceInterval)
		return nil, nil
	}

	var intervals uint64
	if !now.Before(e.performanceNext) {
		intervals = uint64(now.Sub(e.performanceNext)/performanceInterval) + 1
	}
	intervalEnd := e.performanceIntervalEnd + uint8(intervals)
	updates := make(map[mib.Key]me.AttributeValueMap,
		len(e.performanceState)+len(e.fecPMState)+len(e.ethernetPMState)+len(e.xgsPMState))
	baselines := make(map[mib.Key]performance.GEMPortCounters, len(e.performanceState))
	evaluations := make(map[mib.Key]performanceThresholdEvaluation,
		len(e.performanceState)+len(e.fecPMState)+len(e.ethernetPMState)+len(e.xgsPMState))
	for key, state := range e.performanceState {
		rules, err := e.performanceThresholdsLocked(key)
		if err != nil {
			return nil, fmt.Errorf("resolve GEM performance thresholds for %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		if intervals == 0 && len(rules) == 0 {
			continue
		}
		current, err := e.performance.GEMPortCounters(state.portID)
		if err != nil {
			return nil, fmt.Errorf("read GEM port %d performance counters: %w", state.portID, err)
		}
		attributes := zeroGEMPerformanceAttributes(intervalEnd)
		if intervals <= 1 {
			attributes = gemPerformanceAttributes(intervalEnd,
				deltaGEMCounters(state.baseline, current))
		}
		if intervals != 0 {
			updates[key] = attributes
			baselines[key] = current
		}
		if intervals <= 1 && len(rules) != 0 {
			evaluations[key] = performanceThresholdEvaluation{attributes: attributes, rules: rules}
		}
	}
	fecBaselines := make(map[mib.Key]performance.FECCounters, len(e.fecPMState))
	for key, state := range e.fecPMState {
		rules, err := e.performanceThresholdsLocked(key)
		if err != nil {
			return nil, fmt.Errorf("resolve FEC performance thresholds for %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		if intervals == 0 && len(rules) == 0 {
			continue
		}
		current, err := e.fecPerformance.FECCounters(state.aniEntityID)
		if err != nil {
			return nil, fmt.Errorf("read ANI-G %#x FEC performance counters: %w",
				state.aniEntityID, err)
		}
		attributes := fecPerformanceAttributes(intervalEnd, performance.FECCounters{})
		if intervals <= 1 {
			attributes = fecPerformanceAttributes(intervalEnd,
				deltaFECCounters(state.baseline, current))
		}
		if intervals != 0 {
			updates[key] = attributes
			fecBaselines[key] = current
		}
		if intervals <= 1 && len(rules) != 0 {
			evaluations[key] = performanceThresholdEvaluation{attributes: attributes, rules: rules}
		}
	}
	ethernetBaselines := make(map[mib.Key]performance.EthernetCounters, len(e.ethernetPMState))
	for key, state := range e.ethernetPMState {
		rules, err := e.performanceThresholdsLocked(key)
		if err != nil {
			return nil, fmt.Errorf("resolve Ethernet performance thresholds for %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		if intervals == 0 && len(rules) == 0 {
			continue
		}
		current, err := e.ethernetPerformance.EthernetCounters(state.uniEntityID)
		if err != nil {
			return nil, fmt.Errorf("read Ethernet UNI %#x performance counters: %w",
				state.uniEntityID, err)
		}
		attributes := ethernetPerformanceAttributes(key.ClassID, intervalEnd,
			performance.EthernetCounters{})
		if intervals <= 1 {
			attributes = ethernetPerformanceAttributes(key.ClassID, intervalEnd,
				deltaEthernetCounters(state.baseline, current))
		}
		if intervals != 0 {
			updates[key] = attributes
			ethernetBaselines[key] = current
		}
		if intervals <= 1 && len(rules) != 0 {
			evaluations[key] = performanceThresholdEvaluation{attributes: attributes, rules: rules}
		}
	}
	xgsBaselines := make(map[mib.Key]performance.XGSPONCounters, len(e.xgsPMState))
	for key, state := range e.xgsPMState {
		rules, err := e.performanceThresholdsLocked(key)
		if err != nil {
			return nil, fmt.Errorf("resolve XGS-PON performance thresholds for %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		if intervals == 0 && len(rules) == 0 {
			continue
		}
		current, err := e.xgsPerformance.XGSPONCounters(state.aniEntityID)
		if err != nil {
			return nil, fmt.Errorf("read ANI-G %#x XGS-PON performance counters: %w",
				state.aniEntityID, err)
		}
		attributes := xgsPerformanceAttributes(key.ClassID, intervalEnd,
			performance.XGSPONCounters{})
		if intervals <= 1 {
			attributes = xgsPerformanceAttributes(key.ClassID, intervalEnd,
				deltaXGSPONCounters(state.baseline, current))
		}
		if intervals != 0 {
			updates[key] = attributes
			xgsBaselines[key] = current
		}
		if intervals <= 1 && len(rules) != 0 {
			evaluations[key] = performanceThresholdEvaluation{attributes: attributes, rules: rules}
		}
	}
	if intervals != 0 {
		if err := e.mib.UpdateAutonomousBatch(updates); err != nil {
			return nil, fmt.Errorf("update performance history: %w", err)
		}
		for key, baseline := range baselines {
			state := e.performanceState[key]
			state.baseline = baseline
			e.performanceState[key] = state
		}
		for key, baseline := range fecBaselines {
			state := e.fecPMState[key]
			state.baseline = baseline
			e.fecPMState[key] = state
		}
		for key, baseline := range ethernetBaselines {
			state := e.ethernetPMState[key]
			state.baseline = baseline
			e.ethernetPMState[key] = state
		}
		for key, baseline := range xgsBaselines {
			state := e.xgsPMState[key]
			state.baseline = baseline
			e.xgsPMState[key] = state
		}
		e.performanceIntervalEnd = intervalEnd
		e.performanceNext = e.performanceNext.Add(time.Duration(intervals) * performanceInterval)
	}

	keys := make([]mib.Key, 0, len(evaluations))
	for key := range evaluations {
		keys = append(keys, key)
	}
	sortMIBKeys(keys)
	frames := make([][]byte, 0, len(evaluations))
	for _, key := range keys {
		evaluation := evaluations[key]
		frame, emitted, err := e.evaluatePerformanceTCALocked(
			key, evaluation.attributes, evaluation.rules, device)
		if err != nil {
			return frames, fmt.Errorf("evaluate performance TCA for %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		if emitted {
			frames = append(frames, frame)
		}
	}
	if intervals != 0 {
		clears, err := e.clearPerformanceTCANotificationsLocked(device)
		if err != nil {
			return frames, err
		}
		frames = append(frames, clears...)
	}
	return frames, nil
}

func (e *Engine) reconcilePerformanceLocked() error {
	activeGEM := make(map[mib.Key]struct{})
	for _, instance := range e.mib.Snapshot() {
		if instance.ClassID == me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID &&
			e.performance != nil {
			key := instance.Key
			activeGEM[key] = struct{}{}
			parent, err := e.mib.Get(mib.Key{
				ClassID: me.GemPortNetworkCtpClassID, EntityID: key.EntityID,
			}, 0x8000)
			if err != nil {
				return fmt.Errorf("resolve GEM PM parent %#x: %w", key.EntityID, err)
			}
			portID, ok := parent.Attributes[me.GemPortNetworkCtp_PortId].(uint16)
			if !ok || portID > 0x0fff {
				return fmt.Errorf("GEM PM parent %#x has invalid port ID", key.EntityID)
			}
			state, present := e.performanceState[key]
			if present && state.portID == portID {
				continue
			}
			baseline, err := e.performance.GEMPortCounters(portID)
			if err != nil {
				return fmt.Errorf("initialize GEM port %d performance counters: %w", portID, err)
			}
			e.performanceState[key] = performanceState{portID: portID, baseline: baseline}
		}
	}
	for key := range e.performanceState {
		if _, present := activeGEM[key]; !present {
			delete(e.performanceState, key)
		}
	}

	activeFEC := make(map[mib.Key]struct{})
	for _, instance := range e.mib.Snapshot() {
		if instance.ClassID != me.FecPerformanceMonitoringHistoryDataClassID ||
			e.fecPerformance == nil {
			continue
		}
		key := instance.Key
		activeFEC[key] = struct{}{}
		if !e.mib.Exists(mib.Key{ClassID: me.AniGClassID, EntityID: key.EntityID}) {
			return fmt.Errorf("FEC PM references missing ANI-G %#x", key.EntityID)
		}
		if _, present := e.fecPMState[key]; present {
			continue
		}
		baseline, err := e.fecPerformance.FECCounters(key.EntityID)
		if err != nil {
			return fmt.Errorf("initialize ANI-G %#x FEC performance counters: %w",
				key.EntityID, err)
		}
		e.fecPMState[key] = fecPerformanceState{
			aniEntityID: key.EntityID, baseline: baseline,
		}
	}
	for key := range e.fecPMState {
		if _, present := activeFEC[key]; !present {
			delete(e.fecPMState, key)
		}
	}

	activeEthernet := make(map[mib.Key]struct{})
	for _, instance := range e.mib.Snapshot() {
		if !isEthernetPerformanceClass(instance.ClassID) || e.ethernetPerformance == nil {
			continue
		}
		key := instance.Key
		activeEthernet[key] = struct{}{}
		uniEntityID, err := e.resolveEthernetPerformanceUNILocked(key)
		if err != nil {
			return fmt.Errorf("resolve Ethernet PM %v/%#x: %w", key.ClassID, key.EntityID, err)
		}
		state, present := e.ethernetPMState[key]
		if present && state.uniEntityID == uniEntityID {
			continue
		}
		baseline, err := e.ethernetPerformance.EthernetCounters(uniEntityID)
		if err != nil {
			return fmt.Errorf("initialize Ethernet UNI %#x performance counters: %w",
				uniEntityID, err)
		}
		e.ethernetPMState[key] = ethernetPerformanceState{
			uniEntityID: uniEntityID, baseline: baseline,
		}
	}
	for key := range e.ethernetPMState {
		if _, present := activeEthernet[key]; !present {
			delete(e.ethernetPMState, key)
		}
	}

	activeXGS := make(map[mib.Key]struct{})
	for _, instance := range e.mib.Snapshot() {
		if !isXGSPONPerformanceClass(instance.ClassID) || e.xgsPerformance == nil {
			continue
		}
		key := instance.Key
		activeXGS[key] = struct{}{}
		if !e.mib.Exists(mib.Key{ClassID: me.AniGClassID, EntityID: key.EntityID}) {
			return fmt.Errorf("XGS-PON PM references missing ANI-G %#x", key.EntityID)
		}
		if _, present := e.xgsPMState[key]; present {
			continue
		}
		baseline, err := e.xgsPerformance.XGSPONCounters(key.EntityID)
		if err != nil {
			return fmt.Errorf("initialize ANI-G %#x XGS-PON performance counters: %w",
				key.EntityID, err)
		}
		e.xgsPMState[key] = xgsPerformanceState{aniEntityID: key.EntityID, baseline: baseline}
	}
	for key := range e.xgsPMState {
		if _, present := activeXGS[key]; !present {
			delete(e.xgsPMState, key)
		}
	}
	return nil
}

func (e *Engine) getCurrentPerformanceLocked(key mib.Key, mask uint16) (mib.Instance, error) {
	gemPerformance := key.ClassID == me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID
	fecPerformance := key.ClassID == me.FecPerformanceMonitoringHistoryDataClassID
	ethernetPerformance := isEthernetPerformanceClass(key.ClassID)
	xgsPerformance := isXGSPONPerformanceClass(key.ClassID)
	if (!gemPerformance || e.performance == nil) &&
		(!fecPerformance || e.fecPerformance == nil) &&
		(!ethernetPerformance || e.ethernetPerformance == nil) &&
		(!xgsPerformance || e.xgsPerformance == nil) {
		return mib.Instance{}, &mib.ResultError{Result: me.NotSupported}
	}
	if currentDataSize(key.ClassID, mask) > 25 {
		return mib.Instance{}, &mib.ResultError{Result: me.ParameterError}
	}
	if err := e.reconcilePerformanceLocked(); err != nil {
		return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}
	}
	instance, getErr := e.mib.Get(key, mask)
	if instance.Attributes == nil {
		return instance, getErr
	}
	var values me.AttributeValueMap
	if gemPerformance {
		state, present := e.performanceState[key]
		if !present {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		current, err := e.performance.GEMPortCounters(state.portID)
		if err != nil {
			return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}
		}
		values = gemPerformanceAttributes(e.performanceIntervalEnd,
			deltaGEMCounters(state.baseline, current))
	} else if fecPerformance {
		state, present := e.fecPMState[key]
		if !present {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		current, err := e.fecPerformance.FECCounters(state.aniEntityID)
		if err != nil {
			return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}
		}
		values = fecPerformanceAttributes(e.performanceIntervalEnd,
			deltaFECCounters(state.baseline, current))
	} else if ethernetPerformance {
		state, present := e.ethernetPMState[key]
		if !present {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		current, err := e.ethernetPerformance.EthernetCounters(state.uniEntityID)
		if err != nil {
			return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}
		}
		values = ethernetPerformanceAttributes(key.ClassID, e.performanceIntervalEnd,
			deltaEthernetCounters(state.baseline, current))
	} else {
		state, present := e.xgsPMState[key]
		if !present {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		current, err := e.xgsPerformance.XGSPONCounters(state.aniEntityID)
		if err != nil {
			return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}
		}
		values = xgsPerformanceAttributes(key.ClassID, e.performanceIntervalEnd,
			deltaXGSPONCounters(state.baseline, current))
	}
	for name := range instance.Attributes {
		if value, dynamic := values[name]; dynamic {
			instance.Attributes[name] = value
		}
	}
	return instance, getErr
}

func (e *Engine) preparePerformanceSynchronizationLocked() (performanceSynchronization, error) {
	if e.performance == nil && e.fecPerformance == nil && e.ethernetPerformance == nil &&
		e.xgsPerformance == nil {
		return performanceSynchronization{}, nil
	}
	if err := e.reconcilePerformanceLocked(); err != nil {
		return performanceSynchronization{}, err
	}
	baselines := performanceSynchronization{
		gem:      make(map[mib.Key]performance.GEMPortCounters, len(e.performanceState)),
		fec:      make(map[mib.Key]performance.FECCounters, len(e.fecPMState)),
		ethernet: make(map[mib.Key]performance.EthernetCounters, len(e.ethernetPMState)),
		xgs:      make(map[mib.Key]performance.XGSPONCounters, len(e.xgsPMState)),
	}
	for key, state := range e.performanceState {
		current, err := e.performance.GEMPortCounters(state.portID)
		if err != nil {
			return performanceSynchronization{}, fmt.Errorf(
				"synchronize GEM port %d performance counters: %w", state.portID, err)
		}
		baselines.gem[key] = current
	}
	for key, state := range e.fecPMState {
		current, err := e.fecPerformance.FECCounters(state.aniEntityID)
		if err != nil {
			return performanceSynchronization{}, fmt.Errorf(
				"synchronize ANI-G %#x FEC performance counters: %w",
				state.aniEntityID, err)
		}
		baselines.fec[key] = current
	}
	for key, state := range e.ethernetPMState {
		current, err := e.ethernetPerformance.EthernetCounters(state.uniEntityID)
		if err != nil {
			return performanceSynchronization{}, fmt.Errorf(
				"synchronize Ethernet UNI %#x performance counters: %w",
				state.uniEntityID, err)
		}
		baselines.ethernet[key] = current
	}
	for key, state := range e.xgsPMState {
		current, err := e.xgsPerformance.XGSPONCounters(state.aniEntityID)
		if err != nil {
			return performanceSynchronization{}, fmt.Errorf(
				"synchronize ANI-G %#x XGS-PON performance counters: %w",
				state.aniEntityID, err)
		}
		baselines.xgs[key] = current
	}
	return baselines, nil
}

func (e *Engine) commitPerformanceSynchronizationLocked(now time.Time,
	baselines performanceSynchronization) error {
	updates := make(map[mib.Key]me.AttributeValueMap,
		len(baselines.gem)+len(baselines.fec)+len(baselines.ethernet)+len(baselines.xgs))
	for key := range baselines.gem {
		updates[key] = zeroGEMPerformanceAttributes(0)
	}
	for key := range baselines.fec {
		updates[key] = fecPerformanceAttributes(0, performance.FECCounters{})
	}
	for key := range baselines.ethernet {
		updates[key] = ethernetPerformanceAttributes(key.ClassID, 0,
			performance.EthernetCounters{})
	}
	for key := range baselines.xgs {
		updates[key] = xgsPerformanceAttributes(key.ClassID, 0, performance.XGSPONCounters{})
	}
	if err := e.mib.UpdateAutonomousBatch(updates); err != nil {
		return err
	}
	for key, baseline := range baselines.gem {
		state := e.performanceState[key]
		state.baseline = baseline
		e.performanceState[key] = state
	}
	for key, baseline := range baselines.fec {
		state := e.fecPMState[key]
		state.baseline = baseline
		e.fecPMState[key] = state
	}
	for key, baseline := range baselines.ethernet {
		state := e.ethernetPMState[key]
		state.baseline = baseline
		e.ethernetPMState[key] = state
	}
	for key, baseline := range baselines.xgs {
		state := e.xgsPMState[key]
		state.baseline = baseline
		e.xgsPMState[key] = state
	}
	e.performanceIntervalEnd = 0
	e.performanceNext = now.Add(performanceInterval)
	return nil
}

func currentDataSize(classID me.ClassID, mask uint16) int {
	entity, omciErr := me.LoadManagedEntityDefinition(classID, me.ParamData{EntityID: 0})
	if omciErr.StatusCode() != me.Success {
		return 0
	}
	size := 0
	for index, definition := range entity.GetAttributeDefinitions() {
		if index != 0 && mask&definition.Mask != 0 {
			size += definition.GetSize()
		}
	}
	return size
}

func gemPerformanceAttributes(intervalEnd uint8, counters performance.GEMPortCounters) me.AttributeValueMap {
	return me.AttributeValueMap{
		me.GemPortNetworkCtpPerformanceMonitoringHistoryData_IntervalEndTime:         intervalEnd,
		me.GemPortNetworkCtpPerformanceMonitoringHistoryData_TransmittedGemFrames:    saturatingUint32(counters.TransmittedGEMFrames),
		me.GemPortNetworkCtpPerformanceMonitoringHistoryData_ReceivedGemFrames:       saturatingUint32(counters.ReceivedGEMFrames),
		me.GemPortNetworkCtpPerformanceMonitoringHistoryData_ReceivedPayloadBytes:    counters.ReceivedPayloadBytes,
		me.GemPortNetworkCtpPerformanceMonitoringHistoryData_TransmittedPayloadBytes: counters.TransmittedPayloadBytes,
	}
}

func zeroGEMPerformanceAttributes(intervalEnd uint8) me.AttributeValueMap {
	return gemPerformanceAttributes(intervalEnd, performance.GEMPortCounters{})
}

func fecPerformanceAttributes(intervalEnd uint8,
	counters performance.FECCounters) me.AttributeValueMap {
	return me.AttributeValueMap{
		me.FecPerformanceMonitoringHistoryData_IntervalEndTime:        intervalEnd,
		me.FecPerformanceMonitoringHistoryData_CorrectedBytes:         saturatingUint32(counters.CorrectedBytes),
		me.FecPerformanceMonitoringHistoryData_CorrectedCodeWords:     saturatingUint32(counters.CorrectedCodeWords),
		me.FecPerformanceMonitoringHistoryData_UncorrectableCodeWords: saturatingUint32(counters.UncorrectableCodeWords),
		me.FecPerformanceMonitoringHistoryData_TotalCodeWords:         saturatingUint32(counters.TotalCodeWords),
		me.FecPerformanceMonitoringHistoryData_FecSeconds:             saturatingUint16(counters.FECSeconds),
	}
}

func xgsPerformanceAttributes(classID me.ClassID, intervalEnd uint8,
	counters performance.XGSPONCounters) me.AttributeValueMap {
	switch classID {
	case me.XgPonTcPerformanceMonitoringHistoryDataClassID:
		value := counters.TC
		return me.AttributeValueMap{
			me.XgPonTcPerformanceMonitoringHistoryData_IntervalEndTime:                               intervalEnd,
			me.XgPonTcPerformanceMonitoringHistoryData_PsbdHecErrorCount:                             saturatingUint32(value.PSBdHECErrors),
			me.XgPonTcPerformanceMonitoringHistoryData_XgtcHecErrorCount:                             saturatingUint32(value.XGTCHECErrors),
			me.XgPonTcPerformanceMonitoringHistoryData_UnknownProfileCount:                           saturatingUint32(value.UnknownProfiles),
			me.XgPonTcPerformanceMonitoringHistoryData_TransmittedXgPonEncapsulationMethodXgemFrames: saturatingUint32(value.TransmittedXGEMFrames),
			me.XgPonTcPerformanceMonitoringHistoryData_FragmentXgemFrames:                            saturatingUint32(value.FragmentXGEMFrames),
			me.XgPonTcPerformanceMonitoringHistoryData_XgemHecLostWordsCount:                         saturatingUint32(value.XGEMHECLostWords),
			me.XgPonTcPerformanceMonitoringHistoryData_XgemKeyErrors:                                 saturatingUint32(value.XGEMKeyErrors),
			me.XgPonTcPerformanceMonitoringHistoryData_XgemHecErrorCount:                             saturatingUint32(value.XGEMHECErrors),
			me.XgPonTcPerformanceMonitoringHistoryData_TransmittedBytesInNonIdleXgemFrames:           value.TransmittedNonIdleBytes,
			me.XgPonTcPerformanceMonitoringHistoryData_ReceivedBytesInNonIdleXgemFrames:              value.ReceivedNonIdleBytes,
			me.XgPonTcPerformanceMonitoringHistoryData_LossOfDownstreamSynchronizationLodsEventCount: saturatingUint32(value.LODSEvents),
			me.XgPonTcPerformanceMonitoringHistoryData_LodsEventRestoredCount:                        saturatingUint32(value.LODSRestored),
			me.XgPonTcPerformanceMonitoringHistoryData_OnuReactivationByLodsEvents:                   saturatingUint32(value.ONUReactivationsByLODS),
		}
	case me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID:
		value := counters.Downstream
		return me.AttributeValueMap{
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_IntervalEndTime:                         intervalEnd,
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_PloamMessageIntegrityCheckMicErrorCount: saturatingUint32(value.PLOAMMICErrors),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_DownstreamPloamMessagesCount:            saturatingUint32(value.PLOAMMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_ProfileMessagesReceived:                 saturatingUint32(value.ProfileMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_RangingTimeMessagesReceived:             saturatingUint32(value.RangingTimeMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_DeactivateOnuIdMessagesReceived:         saturatingUint32(value.DeactivateONUIDMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_DisableSerialNumberMessagesReceived:     saturatingUint32(value.DisableSerialNumberMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_RequestRegistrationMessagesReceived:     saturatingUint32(value.RequestRegistrationMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_AssignAllocIdMessagesReceived:           saturatingUint32(value.AssignAllocIDMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_KeyControlMessagesReceived:              saturatingUint32(value.KeyControlMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_SleepAllowMessagesReceived:              saturatingUint32(value.SleepAllowMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_BaselineOmciMessagesReceivedCount:       saturatingUint32(value.BaselineOMCIMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_ExtendedOmciMessagesReceivedCount:       saturatingUint32(value.ExtendedOMCIMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_AssignOnuIdMessagesReceived:             saturatingUint32(value.AssignONUIDMessages),
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryData_OmciMicErrorCount:                       saturatingUint32(value.OMCIMICErrors),
		}
	case me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID:
		value := counters.Upstream
		return me.AttributeValueMap{
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_IntervalEndTime:             intervalEnd,
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_UpstreamPloamMessageCount:   saturatingUint32(value.PLOAMMessages),
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_SerialNumberOnuMessageCount: saturatingUint32(value.SerialNumberMessages),
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_RegistrationMessageCount:    saturatingUint32(value.RegistrationMessages),
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_KeyReportMessageCount:       saturatingUint32(value.KeyReportMessages),
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_AcknowledgeMessageCount:     saturatingUint32(value.AcknowledgeMessages),
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryData_SleepRequestMessageCount:    saturatingUint32(value.SleepRequestMessages),
		}
	default:
		return nil
	}
}

func ethernetPerformanceAttributes(classID me.ClassID, intervalEnd uint8,
	counters performance.EthernetCounters) me.AttributeValueMap {
	switch classID {
	case me.EthernetPerformanceMonitoringHistoryDataClassID:
		rx := counters.Received
		tx := counters.Transmitted
		return me.AttributeValueMap{
			me.EthernetPerformanceMonitoringHistoryData_IntervalEndTime:                 intervalEnd,
			me.EthernetPerformanceMonitoringHistoryData_FcsErrors:                       saturatingUint32(rx.CRCErrors),
			me.EthernetPerformanceMonitoringHistoryData_ExcessiveCollisionCounter:       uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_LateCollisionCounter:            uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_FramesTooLong:                   saturatingUint32(rx.OversizeFrames),
			me.EthernetPerformanceMonitoringHistoryData_BufferOverflowsOnReceive:        saturatingUint32(rx.BufferOverflows),
			me.EthernetPerformanceMonitoringHistoryData_BufferOverflowsOnTransmit:       saturatingUint32(tx.BufferOverflows),
			me.EthernetPerformanceMonitoringHistoryData_SingleCollisionFrameCounter:     uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_MultipleCollisionsFrameCounter:  uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_SqeCounter:                      uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_DeferredTransmissionCounter:     uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_InternalMacTransmitErrorCounter: saturatingUint32(tx.InternalErrors),
			me.EthernetPerformanceMonitoringHistoryData_CarrierSenseErrorCounter:        uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_AlignmentErrorCounter:           uint32(0),
			me.EthernetPerformanceMonitoringHistoryData_InternalMacReceiveErrorCounter:  saturatingUint32(rx.InternalErrors),
		}

	case me.EthernetPerformanceMonitoringHistoryData3ClassID:
		rx := counters.Received
		return me.AttributeValueMap{
			me.EthernetPerformanceMonitoringHistoryData3_IntervalEndTime:         intervalEnd,
			me.EthernetPerformanceMonitoringHistoryData3_DropEvents:              saturatingUint32(rx.DropEvents),
			me.EthernetPerformanceMonitoringHistoryData3_Octets:                  saturatingUint32(rx.Octets),
			me.EthernetPerformanceMonitoringHistoryData3_Packets:                 saturatingUint32(rx.Frames),
			me.EthernetPerformanceMonitoringHistoryData3_BroadcastPackets:        saturatingUint32(rx.BroadcastFrames),
			me.EthernetPerformanceMonitoringHistoryData3_MulticastPackets:        saturatingUint32(rx.MulticastFrames),
			me.EthernetPerformanceMonitoringHistoryData3_UndersizePackets:        saturatingUint32(rx.UndersizeFrames),
			me.EthernetPerformanceMonitoringHistoryData3_Fragments:               saturatingUint32(rx.Fragments),
			me.EthernetPerformanceMonitoringHistoryData3_Jabbers:                 saturatingUint32(rx.Jabbers),
			me.EthernetPerformanceMonitoringHistoryData3_Packets64Octets:         saturatingUint32(rx.SizeBuckets[0]),
			me.EthernetPerformanceMonitoringHistoryData3_Packets65To127Octets:    saturatingUint32(rx.SizeBuckets[1]),
			me.EthernetPerformanceMonitoringHistoryData3_Packets128To255Octets:   saturatingUint32(rx.SizeBuckets[2]),
			me.EthernetPerformanceMonitoringHistoryData3_Packets256To511Octets:   saturatingUint32(rx.SizeBuckets[3]),
			me.EthernetPerformanceMonitoringHistoryData3_Packets512To1023Octets:  saturatingUint32(rx.SizeBuckets[4]),
			me.EthernetPerformanceMonitoringHistoryData3_Packets1024To1518Octets: saturatingUint32(rx.SizeBuckets[5]),
		}

	case me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID:
		return ethernetFrameDownstreamAttributes(intervalEnd, counters.Transmitted)
	case me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID:
		return ethernetFrameUpstreamAttributes(intervalEnd, counters.Received)
	default:
		return nil
	}
}

func ethernetFrameDownstreamAttributes(intervalEnd uint8,
	counters performance.EthernetDirectionCounters) me.AttributeValueMap {
	return me.AttributeValueMap{
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_IntervalEndTime:         intervalEnd,
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_DropEvents:              saturatingUint32(counters.DropEvents),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Octets:                  saturatingUint32(counters.Octets),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets:                 saturatingUint32(counters.Frames),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_BroadcastPackets:        saturatingUint32(counters.BroadcastFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_MulticastPackets:        saturatingUint32(counters.MulticastFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_CrcErroredPackets:       saturatingUint32(counters.CRCErrors),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_UndersizePackets:        saturatingUint32(counters.UndersizeFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_OversizePackets:         saturatingUint32(counters.OversizeFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets64Octets:         saturatingUint32(counters.SizeBuckets[0]),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets65To127Octets:    saturatingUint32(counters.SizeBuckets[1]),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets128To255Octets:   saturatingUint32(counters.SizeBuckets[2]),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets256To511Octets:   saturatingUint32(counters.SizeBuckets[3]),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets512To1023Octets:  saturatingUint32(counters.SizeBuckets[4]),
		me.EthernetFramePerformanceMonitoringHistoryDataDownstream_Packets1024To1518Octets: saturatingUint32(counters.SizeBuckets[5]),
	}
}

func ethernetFrameUpstreamAttributes(intervalEnd uint8,
	counters performance.EthernetDirectionCounters) me.AttributeValueMap {
	return me.AttributeValueMap{
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_IntervalEndTime:         intervalEnd,
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_DropEvents:              saturatingUint32(counters.DropEvents),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Octets:                  saturatingUint32(counters.Octets),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets:                 saturatingUint32(counters.Frames),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_BroadcastPackets:        saturatingUint32(counters.BroadcastFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_MulticastPackets:        saturatingUint32(counters.MulticastFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_CrcErroredPackets:       saturatingUint32(counters.CRCErrors),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_UndersizePackets:        saturatingUint32(counters.UndersizeFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_OversizePackets:         saturatingUint32(counters.OversizeFrames),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets64Octets:         saturatingUint32(counters.SizeBuckets[0]),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets65To127Octets:    saturatingUint32(counters.SizeBuckets[1]),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets128To255Octets:   saturatingUint32(counters.SizeBuckets[2]),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets256To511Octets:   saturatingUint32(counters.SizeBuckets[3]),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets512To1023Octets:  saturatingUint32(counters.SizeBuckets[4]),
		me.EthernetFramePerformanceMonitoringHistoryDataUpstream_Packets1024To1518Octets: saturatingUint32(counters.SizeBuckets[5]),
	}
}

func deltaGEMCounters(start, current performance.GEMPortCounters) performance.GEMPortCounters {
	return performance.GEMPortCounters{
		ReceivedGEMFrames:       counterDelta(start.ReceivedGEMFrames, current.ReceivedGEMFrames),
		ReceivedPayloadBytes:    counterDelta(start.ReceivedPayloadBytes, current.ReceivedPayloadBytes),
		TransmittedGEMFrames:    counterDelta(start.TransmittedGEMFrames, current.TransmittedGEMFrames),
		TransmittedPayloadBytes: counterDelta(start.TransmittedPayloadBytes, current.TransmittedPayloadBytes),
	}
}

func deltaFECCounters(start, current performance.FECCounters) performance.FECCounters {
	return performance.FECCounters{
		CorrectedBytes:         counterDelta(start.CorrectedBytes, current.CorrectedBytes),
		CorrectedCodeWords:     counterDelta(start.CorrectedCodeWords, current.CorrectedCodeWords),
		UncorrectableCodeWords: counterDelta(start.UncorrectableCodeWords, current.UncorrectableCodeWords),
		TotalCodeWords:         counterDelta(start.TotalCodeWords, current.TotalCodeWords),
		FECSeconds:             counterDelta(start.FECSeconds, current.FECSeconds),
	}
}

func deltaEthernetCounters(start, current performance.EthernetCounters) performance.EthernetCounters {
	return performance.EthernetCounters{
		Received:    deltaEthernetDirection(start.Received, current.Received),
		Transmitted: deltaEthernetDirection(start.Transmitted, current.Transmitted),
	}
}

func deltaEthernetDirection(start, current performance.EthernetDirectionCounters) performance.EthernetDirectionCounters {
	delta := performance.EthernetDirectionCounters{
		Frames:          counterDelta(start.Frames, current.Frames),
		Octets:          counterDelta(start.Octets, current.Octets),
		DropEvents:      counterDelta(start.DropEvents, current.DropEvents),
		BroadcastFrames: counterDelta(start.BroadcastFrames, current.BroadcastFrames),
		MulticastFrames: counterDelta(start.MulticastFrames, current.MulticastFrames),
		CRCErrors:       counterDelta(start.CRCErrors, current.CRCErrors),
		BufferOverflows: counterDelta(start.BufferOverflows, current.BufferOverflows),
		InternalErrors:  counterDelta(start.InternalErrors, current.InternalErrors),
		UndersizeFrames: counterDelta(start.UndersizeFrames, current.UndersizeFrames),
		Fragments:       counterDelta(start.Fragments, current.Fragments),
		Jabbers:         counterDelta(start.Jabbers, current.Jabbers),
		OversizeFrames:  counterDelta(start.OversizeFrames, current.OversizeFrames),
	}
	for index := range delta.SizeBuckets {
		delta.SizeBuckets[index] = counterDelta(start.SizeBuckets[index], current.SizeBuckets[index])
	}
	return delta
}

func deltaXGSPONCounters(start, current performance.XGSPONCounters) performance.XGSPONCounters {
	return performance.XGSPONCounters{
		TC: performance.XGSPONTCCounters{
			PSBdHECErrors:           counterDelta(start.TC.PSBdHECErrors, current.TC.PSBdHECErrors),
			XGTCHECErrors:           counterDelta(start.TC.XGTCHECErrors, current.TC.XGTCHECErrors),
			UnknownProfiles:         counterDelta(start.TC.UnknownProfiles, current.TC.UnknownProfiles),
			TransmittedXGEMFrames:   counterDelta(start.TC.TransmittedXGEMFrames, current.TC.TransmittedXGEMFrames),
			FragmentXGEMFrames:      counterDelta(start.TC.FragmentXGEMFrames, current.TC.FragmentXGEMFrames),
			XGEMHECLostWords:        counterDelta(start.TC.XGEMHECLostWords, current.TC.XGEMHECLostWords),
			XGEMKeyErrors:           counterDelta(start.TC.XGEMKeyErrors, current.TC.XGEMKeyErrors),
			XGEMHECErrors:           counterDelta(start.TC.XGEMHECErrors, current.TC.XGEMHECErrors),
			TransmittedNonIdleBytes: counterDelta(start.TC.TransmittedNonIdleBytes, current.TC.TransmittedNonIdleBytes),
			ReceivedNonIdleBytes:    counterDelta(start.TC.ReceivedNonIdleBytes, current.TC.ReceivedNonIdleBytes),
			LODSEvents:              counterDelta(start.TC.LODSEvents, current.TC.LODSEvents),
			LODSRestored:            counterDelta(start.TC.LODSRestored, current.TC.LODSRestored),
			ONUReactivationsByLODS:  counterDelta(start.TC.ONUReactivationsByLODS, current.TC.ONUReactivationsByLODS),
		},
		Downstream: performance.XGSPONDownstreamManagementCounters{
			PLOAMMICErrors:              counterDelta(start.Downstream.PLOAMMICErrors, current.Downstream.PLOAMMICErrors),
			PLOAMMessages:               counterDelta(start.Downstream.PLOAMMessages, current.Downstream.PLOAMMessages),
			ProfileMessages:             counterDelta(start.Downstream.ProfileMessages, current.Downstream.ProfileMessages),
			RangingTimeMessages:         counterDelta(start.Downstream.RangingTimeMessages, current.Downstream.RangingTimeMessages),
			DeactivateONUIDMessages:     counterDelta(start.Downstream.DeactivateONUIDMessages, current.Downstream.DeactivateONUIDMessages),
			DisableSerialNumberMessages: counterDelta(start.Downstream.DisableSerialNumberMessages, current.Downstream.DisableSerialNumberMessages),
			RequestRegistrationMessages: counterDelta(start.Downstream.RequestRegistrationMessages, current.Downstream.RequestRegistrationMessages),
			AssignAllocIDMessages:       counterDelta(start.Downstream.AssignAllocIDMessages, current.Downstream.AssignAllocIDMessages),
			KeyControlMessages:          counterDelta(start.Downstream.KeyControlMessages, current.Downstream.KeyControlMessages),
			SleepAllowMessages:          counterDelta(start.Downstream.SleepAllowMessages, current.Downstream.SleepAllowMessages),
			BaselineOMCIMessages:        counterDelta(start.Downstream.BaselineOMCIMessages, current.Downstream.BaselineOMCIMessages),
			ExtendedOMCIMessages:        counterDelta(start.Downstream.ExtendedOMCIMessages, current.Downstream.ExtendedOMCIMessages),
			AssignONUIDMessages:         counterDelta(start.Downstream.AssignONUIDMessages, current.Downstream.AssignONUIDMessages),
			OMCIMICErrors:               counterDelta(start.Downstream.OMCIMICErrors, current.Downstream.OMCIMICErrors),
		},
		Upstream: performance.XGSPONUpstreamManagementCounters{
			PLOAMMessages:        counterDelta(start.Upstream.PLOAMMessages, current.Upstream.PLOAMMessages),
			SerialNumberMessages: counterDelta(start.Upstream.SerialNumberMessages, current.Upstream.SerialNumberMessages),
			RegistrationMessages: counterDelta(start.Upstream.RegistrationMessages, current.Upstream.RegistrationMessages),
			KeyReportMessages:    counterDelta(start.Upstream.KeyReportMessages, current.Upstream.KeyReportMessages),
			AcknowledgeMessages:  counterDelta(start.Upstream.AcknowledgeMessages, current.Upstream.AcknowledgeMessages),
			SleepRequestMessages: counterDelta(start.Upstream.SleepRequestMessages, current.Upstream.SleepRequestMessages),
		},
	}
}

func counterDelta(start, current uint64) uint64 {
	if current < start {
		return current
	}
	return current - start
}

func saturatingUint32(value uint64) uint32 {
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

func saturatingUint16(value uint64) uint16 {
	if value > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(value)
}

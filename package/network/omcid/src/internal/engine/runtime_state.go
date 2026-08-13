// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/performance"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

const RuntimeStateVersion = 2

// RuntimeState contains the volatile G.988 state that must survive an OMCI
// daemon restart. The MIB data sync and fingerprint bind it to one committed
// ONU MIB; transaction replay and upload sessions intentionally remain local
// to one OMCC communication session.
type RuntimeState struct {
	Version                uint8                        `json:"version"`
	PONMode                pon.Mode                     `json:"pon_mode"`
	MIBDataSync            uint8                        `json:"mib_data_sync"`
	MIBFingerprint         string                       `json:"mib_fingerprint"`
	AlarmSequence          uint8                        `json:"alarm_sequence"`
	Alarms                 []RuntimeAlarm               `json:"alarms"`
	ARC                    []RuntimeARC                 `json:"arc"`
	BERSamples             []RuntimeBERSample           `json:"ber_samples"`
	PerformanceNext        time.Time                    `json:"performance_next"`
	PerformanceIntervalEnd uint8                        `json:"performance_interval_end"`
	GEMPerformance         []RuntimeGEMPerformance      `json:"gem_performance"`
	FECPerformance         []RuntimeFECPerformance      `json:"fec_performance"`
	EthernetPerformance    []RuntimeEthernetPerformance `json:"ethernet_performance"`
	XGSPerformance         []RuntimeXGSPerformance      `json:"xgs_performance"`
	PerformanceTCA         []RuntimeAlarm               `json:"performance_tca"`
}

type RuntimeAlarm struct {
	Key    mib.Key  `json:"key"`
	Bitmap [28]byte `json:"bitmap"`
}

type RuntimeARC struct {
	Key       mib.Key   `json:"key"`
	FreeSince time.Time `json:"free_since"`
}

type RuntimeBERSample struct {
	Key    mib.Key   `json:"key"`
	Sample BERSample `json:"sample"`
}

type RuntimeCounter struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

type RuntimeGEMPerformance struct {
	Key      mib.Key                     `json:"key"`
	PortID   uint16                      `json:"port_id"`
	Baseline performance.GEMPortCounters `json:"baseline"`
	History  []RuntimeCounter            `json:"history"`
}

type RuntimeFECPerformance struct {
	Key         mib.Key                 `json:"key"`
	ANIEntityID uint16                  `json:"ani_entity_id"`
	Baseline    performance.FECCounters `json:"baseline"`
	History     []RuntimeCounter        `json:"history"`
}

type RuntimeEthernetPerformance struct {
	Key         mib.Key                      `json:"key"`
	UNIEntityID uint16                       `json:"uni_entity_id"`
	Baseline    performance.EthernetCounters `json:"baseline"`
	History     []RuntimeCounter             `json:"history"`
}

type RuntimeXGSPerformance struct {
	Key         mib.Key                    `json:"key"`
	ANIEntityID uint16                     `json:"ani_entity_id"`
	Baseline    performance.XGSPONCounters `json:"baseline"`
	History     []RuntimeCounter           `json:"history"`
}

// ExportRuntimeState returns a deterministic snapshot. An unchanged engine
// produces identical JSON, allowing the daemon to avoid periodic flash writes.
func (e *Engine) ExportRuntimeState() (RuntimeState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.reconcilePerformanceLocked(); err != nil {
		return RuntimeState{}, fmt.Errorf("reconcile performance state: %w", err)
	}

	snapshot := e.mib.Snapshot()
	fingerprint, err := runtimeMIBFingerprint(snapshot)
	if err != nil {
		return RuntimeState{}, err
	}
	instances := make(map[mib.Key]mib.Instance, len(snapshot))
	for _, instance := range snapshot {
		instances[instance.Key] = instance
	}
	state := RuntimeState{
		Version: RuntimeStateVersion, PONMode: e.ponMode, MIBDataSync: e.mib.DataSync(),
		MIBFingerprint: fingerprint, AlarmSequence: e.alarmSequence,
		PerformanceNext: e.performanceNext, PerformanceIntervalEnd: e.performanceIntervalEnd,
		Alarms:              make([]RuntimeAlarm, 0, len(e.alarms)),
		ARC:                 make([]RuntimeARC, 0, len(e.arcFreeSince)),
		BERSamples:          make([]RuntimeBERSample, 0, len(e.berSample)),
		GEMPerformance:      make([]RuntimeGEMPerformance, 0, len(e.performanceState)),
		FECPerformance:      make([]RuntimeFECPerformance, 0, len(e.fecPMState)),
		EthernetPerformance: make([]RuntimeEthernetPerformance, 0, len(e.ethernetPMState)),
		XGSPerformance:      make([]RuntimeXGSPerformance, 0, len(e.xgsPMState)),
		PerformanceTCA:      make([]RuntimeAlarm, 0, len(e.performanceTCA)),
	}
	for key, bitmap := range e.alarms {
		state.Alarms = append(state.Alarms, RuntimeAlarm{Key: key, Bitmap: bitmap})
	}
	for key, since := range e.arcFreeSince {
		state.ARC = append(state.ARC, RuntimeARC{Key: key, FreeSince: since})
	}
	for key, sample := range e.berSample {
		state.BERSamples = append(state.BERSamples, RuntimeBERSample{Key: key, Sample: sample})
	}
	for key, value := range e.performanceState {
		history, err := runtimePerformanceHistory(instances[key])
		if err != nil {
			return RuntimeState{}, fmt.Errorf("export GEM performance %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		state.GEMPerformance = append(state.GEMPerformance, RuntimeGEMPerformance{
			Key: key, PortID: value.portID, Baseline: value.baseline, History: history,
		})
	}
	for key, value := range e.fecPMState {
		history, err := runtimePerformanceHistory(instances[key])
		if err != nil {
			return RuntimeState{}, fmt.Errorf("export FEC performance %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		state.FECPerformance = append(state.FECPerformance, RuntimeFECPerformance{
			Key: key, ANIEntityID: value.aniEntityID, Baseline: value.baseline, History: history,
		})
	}
	for key, value := range e.ethernetPMState {
		history, err := runtimePerformanceHistory(instances[key])
		if err != nil {
			return RuntimeState{}, fmt.Errorf("export Ethernet performance %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		state.EthernetPerformance = append(state.EthernetPerformance, RuntimeEthernetPerformance{
			Key: key, UNIEntityID: value.uniEntityID, Baseline: value.baseline, History: history,
		})
	}
	for key, value := range e.xgsPMState {
		history, err := runtimePerformanceHistory(instances[key])
		if err != nil {
			return RuntimeState{}, fmt.Errorf("export XGS-PON performance %v/%#x: %w",
				key.ClassID, key.EntityID, err)
		}
		state.XGSPerformance = append(state.XGSPerformance, RuntimeXGSPerformance{
			Key: key, ANIEntityID: value.aniEntityID, Baseline: value.baseline, History: history,
		})
	}
	for key, bitmap := range e.performanceTCA {
		state.PerformanceTCA = append(state.PerformanceTCA, RuntimeAlarm{Key: key, Bitmap: bitmap})
	}
	sortRuntimeState(&state)
	return state, nil
}

// RestoreRuntimeState validates the complete document before changing either
// the engine or the dynamic PM history in the MIB.
func (e *Engine) RestoreRuntimeState(state RuntimeState) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if state.Version != RuntimeStateVersion {
		return fmt.Errorf("unsupported runtime state version %d", state.Version)
	}
	if state.PONMode != e.ponMode {
		return fmt.Errorf("runtime PON mode %q does not match configured mode %q",
			state.PONMode, e.ponMode)
	}
	if state.MIBDataSync != e.mib.DataSync() {
		return fmt.Errorf("runtime MIB data sync %d does not match current MIB %d",
			state.MIBDataSync, e.mib.DataSync())
	}
	snapshot := e.mib.Snapshot()
	fingerprint, err := runtimeMIBFingerprint(snapshot)
	if err != nil {
		return err
	}
	if state.MIBFingerprint != fingerprint {
		return fmt.Errorf("runtime MIB fingerprint does not match the current ONU MIB")
	}
	instances := make(map[mib.Key]mib.Instance, len(snapshot))
	for _, instance := range snapshot {
		instances[instance.Key] = instance
	}

	alarms, err := e.validateRuntimeAlarmsLocked(state.Alarms)
	if err != nil {
		return err
	}
	tca, err := e.validateRuntimeTCALocked(state.PerformanceTCA, alarms)
	if err != nil {
		return err
	}
	arc, err := e.validateRuntimeARCLocked(state.ARC, alarms)
	if err != nil {
		return err
	}
	berSamples, err := e.validateRuntimeBERSamplesLocked(state.BERSamples)
	if err != nil {
		return err
	}

	gem, fec, ethernet, xgs, histories, err := e.validateRuntimePerformanceLocked(state, instances)
	if err != nil {
		return err
	}
	if err := e.mib.UpdateAutonomousBatch(histories); err != nil {
		return fmt.Errorf("restore performance history: %w", err)
	}

	e.alarms = alarms
	e.alarmSequence = state.AlarmSequence
	e.arcFreeSince = arc
	e.berSample = berSamples
	e.performanceState = gem
	e.fecPMState = fec
	e.ethernetPMState = ethernet
	e.xgsPMState = xgs
	e.performanceTCA = tca
	e.performanceNext = state.PerformanceNext
	e.performanceIntervalEnd = state.PerformanceIntervalEnd
	return nil
}

func (e *Engine) validateRuntimeBERSamplesLocked(values []RuntimeBERSample) (map[mib.Key]BERSample, error) {
	result := make(map[mib.Key]BERSample, len(values))
	for _, value := range values {
		if value.Key.ClassID != me.AniGClassID {
			return nil, fmt.Errorf("runtime BER sample target %v/%#x is not ANI-G",
				value.Key.ClassID, value.Key.EntityID)
		}
		if _, duplicate := result[value.Key]; duplicate {
			return nil, fmt.Errorf("duplicate runtime BER sample %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if !e.mib.Exists(value.Key) {
			return nil, fmt.Errorf("runtime BER sample target %v/%#x does not exist",
				value.Key.ClassID, value.Key.EntityID)
		}
		if err := validateBERSample(value.Sample); err != nil {
			return nil, fmt.Errorf("runtime BER sample %v/%#x: %w",
				value.Key.ClassID, value.Key.EntityID, err)
		}
		result[value.Key] = value.Sample
	}
	return result, nil
}

func (e *Engine) validateRuntimeAlarmsLocked(values []RuntimeAlarm) (map[mib.Key][28]byte, error) {
	result := make(map[mib.Key][28]byte, len(values))
	for _, value := range values {
		if _, duplicate := result[value.Key]; duplicate {
			return nil, fmt.Errorf("duplicate runtime alarm %v/%#x", value.Key.ClassID, value.Key.EntityID)
		}
		if value.Bitmap == ([28]byte{}) {
			return nil, fmt.Errorf("runtime alarm %v/%#x has an empty bitmap",
				value.Key.ClassID, value.Key.EntityID)
		}
		if !e.mib.Exists(value.Key) {
			return nil, fmt.Errorf("runtime alarm target %v/%#x does not exist",
				value.Key.ClassID, value.Key.EntityID)
		}
		entity, omciErr := me.LoadManagedEntityDefinition(value.Key.ClassID,
			me.ParamData{EntityID: value.Key.EntityID})
		if omciErr.StatusCode() != me.Success {
			return nil, omciErr.GetError()
		}
		if err := validateAlarmBitmap(entity.GetAlarmMap(), value.Bitmap); err != nil {
			return nil, fmt.Errorf("runtime alarm %v/%#x: %w",
				value.Key.ClassID, value.Key.EntityID, err)
		}
		if err := e.validateCapabilityAlarmLocked(value.Key.ClassID, value.Bitmap); err != nil {
			return nil, fmt.Errorf("runtime alarm %v/%#x: %w",
				value.Key.ClassID, value.Key.EntityID, err)
		}
		result[value.Key] = value.Bitmap
	}
	return result, nil
}

func (e *Engine) validateRuntimeTCALocked(values []RuntimeAlarm,
	alarms map[mib.Key][28]byte) (map[mib.Key][28]byte, error) {
	result := make(map[mib.Key][28]byte, len(values))
	for _, value := range values {
		if _, duplicate := result[value.Key]; duplicate {
			return nil, fmt.Errorf("duplicate runtime performance TCA %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if !isPerformanceClass(value.Key.ClassID) {
			return nil, fmt.Errorf("runtime TCA target %v/%#x is not a performance ME",
				value.Key.ClassID, value.Key.EntityID)
		}
		if alarm, present := alarms[value.Key]; !present || alarm != value.Bitmap ||
			value.Bitmap == ([28]byte{}) {
			return nil, fmt.Errorf("runtime TCA %v/%#x does not match the alarm audit",
				value.Key.ClassID, value.Key.EntityID)
		}
		result[value.Key] = value.Bitmap
	}
	return result, nil
}

func (e *Engine) validateRuntimeARCLocked(values []RuntimeARC,
	alarms map[mib.Key][28]byte) (map[mib.Key]time.Time, error) {
	result := make(map[mib.Key]time.Time, len(values))
	now := e.now()
	for _, value := range values {
		if _, duplicate := result[value.Key]; duplicate {
			return nil, fmt.Errorf("duplicate runtime ARC timer %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if value.FreeSince.IsZero() || value.FreeSince.After(now.Add(time.Minute)) {
			return nil, fmt.Errorf("runtime ARC timer %v/%#x has invalid start time %v",
				value.Key.ClassID, value.Key.EntityID, value.FreeSince)
		}
		enabled, _, supported, err := e.arcConfigurationLocked(value.Key)
		if err != nil || !supported || !enabled {
			if err == nil {
				err = fmt.Errorf("ARC is not enabled")
			}
			return nil, fmt.Errorf("runtime ARC timer %v/%#x: %w",
				value.Key.ClassID, value.Key.EntityID, err)
		}
		if arcGroupHasAlarm(value.Key, alarms, e) {
			return nil, fmt.Errorf("runtime ARC timer %v/%#x has an active alarm",
				value.Key.ClassID, value.Key.EntityID)
		}
		result[value.Key] = value.FreeSince
	}
	return result, nil
}

func arcGroupHasAlarm(owner mib.Key, alarms map[mib.Key][28]byte, e *Engine) bool {
	for key, bitmap := range alarms {
		if bitmap == ([28]byte{}) {
			continue
		}
		candidate, supported, err := e.arcOwnerLocked(key)
		if err == nil && supported && candidate == owner {
			return true
		}
	}
	return false
}

func (e *Engine) validateRuntimePerformanceLocked(state RuntimeState,
	instances map[mib.Key]mib.Instance) (map[mib.Key]performanceState,
	map[mib.Key]fecPerformanceState, map[mib.Key]ethernetPerformanceState,
	map[mib.Key]xgsPerformanceState, map[mib.Key]me.AttributeValueMap, error) {

	gem := make(map[mib.Key]performanceState, len(state.GEMPerformance))
	fec := make(map[mib.Key]fecPerformanceState, len(state.FECPerformance))
	ethernet := make(map[mib.Key]ethernetPerformanceState, len(state.EthernetPerformance))
	xgs := make(map[mib.Key]xgsPerformanceState, len(state.XGSPerformance))
	histories := make(map[mib.Key]me.AttributeValueMap,
		len(state.GEMPerformance)+len(state.FECPerformance)+len(state.EthernetPerformance)+len(state.XGSPerformance))

	for _, value := range state.GEMPerformance {
		if value.Key.ClassID != me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid GEM runtime key %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if _, duplicate := gem[value.Key]; duplicate {
			return nil, nil, nil, nil, nil, fmt.Errorf("duplicate GEM runtime key %#x", value.Key.EntityID)
		}
		if e.performance == nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("GEM runtime state has no counter backend")
		}
		parent, err := e.mib.Get(mib.Key{ClassID: me.GemPortNetworkCtpClassID,
			EntityID: value.Key.EntityID}, 0x8000)
		if err != nil || parent.Attributes[me.GemPortNetworkCtp_PortId] != value.PortID {
			return nil, nil, nil, nil, nil, fmt.Errorf("GEM runtime key %#x has a stale port ID",
				value.Key.EntityID)
		}
		current, err := e.performance.GEMPortCounters(value.PortID)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("validate GEM port %d counters: %w", value.PortID, err)
		}
		if !gemCountersAtLeast(current, value.Baseline) {
			return nil, nil, nil, nil, nil, fmt.Errorf("GEM port %d counters reset below the saved baseline", value.PortID)
		}
		history, err := restoreRuntimeHistory(instances[value.Key], value.History)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("restore GEM history %#x: %w", value.Key.EntityID, err)
		}
		gem[value.Key] = performanceState{portID: value.PortID, baseline: value.Baseline}
		histories[value.Key] = history
	}
	for _, value := range state.FECPerformance {
		if value.Key.ClassID != me.FecPerformanceMonitoringHistoryDataClassID ||
			value.ANIEntityID != value.Key.EntityID {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid FEC runtime key %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if _, duplicate := fec[value.Key]; duplicate {
			return nil, nil, nil, nil, nil, fmt.Errorf("duplicate FEC runtime key %#x", value.Key.EntityID)
		}
		if e.fecPerformance == nil || !e.mib.Exists(mib.Key{ClassID: me.AniGClassID,
			EntityID: value.ANIEntityID}) {
			return nil, nil, nil, nil, nil, fmt.Errorf("FEC runtime key %#x has no ANI counter backend", value.Key.EntityID)
		}
		current, err := e.fecPerformance.FECCounters(value.ANIEntityID)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("validate ANI-G %#x FEC counters: %w", value.ANIEntityID, err)
		}
		if !fecCountersAtLeast(current, value.Baseline) {
			return nil, nil, nil, nil, nil, fmt.Errorf("ANI-G %#x FEC counters reset below the saved baseline", value.ANIEntityID)
		}
		history, err := restoreRuntimeHistory(instances[value.Key], value.History)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("restore FEC history %#x: %w", value.Key.EntityID, err)
		}
		fec[value.Key] = fecPerformanceState{aniEntityID: value.ANIEntityID, baseline: value.Baseline}
		histories[value.Key] = history
	}
	for _, value := range state.EthernetPerformance {
		if !isEthernetPerformanceClass(value.Key.ClassID) {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid Ethernet runtime key %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if _, duplicate := ethernet[value.Key]; duplicate {
			return nil, nil, nil, nil, nil, fmt.Errorf("duplicate Ethernet runtime key %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if e.ethernetPerformance == nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("Ethernet runtime state has no counter backend")
		}
		resolved, err := e.resolveEthernetPerformanceUNILocked(value.Key)
		if err != nil || resolved != value.UNIEntityID {
			return nil, nil, nil, nil, nil, fmt.Errorf("Ethernet runtime key %v/%#x has a stale UNI",
				value.Key.ClassID, value.Key.EntityID)
		}
		current, err := e.ethernetPerformance.EthernetCounters(value.UNIEntityID)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("validate Ethernet UNI %#x counters: %w", value.UNIEntityID, err)
		}
		if !ethernetCountersAtLeast(current, value.Baseline) {
			return nil, nil, nil, nil, nil, fmt.Errorf("Ethernet UNI %#x counters reset below the saved baseline", value.UNIEntityID)
		}
		history, err := restoreRuntimeHistory(instances[value.Key], value.History)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("restore Ethernet history %v/%#x: %w",
				value.Key.ClassID, value.Key.EntityID, err)
		}
		ethernet[value.Key] = ethernetPerformanceState{
			uniEntityID: value.UNIEntityID, baseline: value.Baseline,
		}
		histories[value.Key] = history
	}
	for _, value := range state.XGSPerformance {
		if !isXGSPONPerformanceClass(value.Key.ClassID) || value.ANIEntityID != value.Key.EntityID {
			return nil, nil, nil, nil, nil, fmt.Errorf("invalid XGS-PON runtime key %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if _, duplicate := xgs[value.Key]; duplicate {
			return nil, nil, nil, nil, nil, fmt.Errorf("duplicate XGS-PON runtime key %v/%#x",
				value.Key.ClassID, value.Key.EntityID)
		}
		if e.xgsPerformance == nil || !e.mib.Exists(mib.Key{
			ClassID: me.AniGClassID, EntityID: value.ANIEntityID,
		}) {
			return nil, nil, nil, nil, nil, fmt.Errorf("XGS-PON runtime key %#x has no ANI counter backend",
				value.Key.EntityID)
		}
		current, err := e.xgsPerformance.XGSPONCounters(value.ANIEntityID)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("validate ANI-G %#x XGS-PON counters: %w",
				value.ANIEntityID, err)
		}
		if !xgsCountersAtLeast(current, value.Baseline) {
			return nil, nil, nil, nil, nil, fmt.Errorf("ANI-G %#x XGS-PON counters reset below the saved baseline",
				value.ANIEntityID)
		}
		history, err := restoreRuntimeHistory(instances[value.Key], value.History)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("restore XGS-PON history %v/%#x: %w",
				value.Key.ClassID, value.Key.EntityID, err)
		}
		xgs[value.Key] = xgsPerformanceState{aniEntityID: value.ANIEntityID, baseline: value.Baseline}
		histories[value.Key] = history
	}

	for key, instance := range instances {
		switch {
		case key.ClassID == me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID && e.performance != nil:
			if _, present := gem[key]; !present {
				return nil, nil, nil, nil, nil, fmt.Errorf("runtime state is missing GEM performance %#x", key.EntityID)
			}
		case key.ClassID == me.FecPerformanceMonitoringHistoryDataClassID && e.fecPerformance != nil:
			if _, present := fec[key]; !present {
				return nil, nil, nil, nil, nil, fmt.Errorf("runtime state is missing FEC performance %#x", key.EntityID)
			}
		case isEthernetPerformanceClass(instance.ClassID) && e.ethernetPerformance != nil:
			if _, present := ethernet[key]; !present {
				return nil, nil, nil, nil, nil, fmt.Errorf("runtime state is missing Ethernet performance %v/%#x",
					key.ClassID, key.EntityID)
			}
		case isXGSPONPerformanceClass(instance.ClassID) && e.xgsPerformance != nil:
			if _, present := xgs[key]; !present {
				return nil, nil, nil, nil, nil, fmt.Errorf("runtime state is missing XGS-PON performance %v/%#x",
					key.ClassID, key.EntityID)
			}
		}
	}
	return gem, fec, ethernet, xgs, histories, nil
}

func runtimePerformanceHistory(instance mib.Instance) ([]RuntimeCounter, error) {
	if instance.Attributes == nil {
		return nil, fmt.Errorf("performance ME does not exist")
	}
	entity, omciErr := me.LoadManagedEntityDefinition(instance.ClassID,
		me.ParamData{EntityID: instance.EntityID})
	if omciErr.StatusCode() != me.Success {
		return nil, omciErr.GetError()
	}
	definitions := entity.GetAttributeDefinitions()
	result := make([]RuntimeCounter, 0, len(instance.Attributes))
	for name, value := range instance.Attributes {
		if name == me.ManagedEntityID {
			continue
		}
		definition, err := me.GetAttributeDefinitionByName(definitions, name)
		if err != nil {
			return nil, err
		}
		if me.SupportsAttributeAccess(*definition, me.Write) ||
			me.SupportsAttributeAccess(*definition, me.SetByCreate) {
			continue
		}
		unsigned, ok := runtimeUnsigned(value)
		if !ok {
			return nil, fmt.Errorf("read-only attribute %s has unsupported type %T", name, value)
		}
		result = append(result, RuntimeCounter{Name: name, Value: unsigned})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func restoreRuntimeHistory(instance mib.Instance,
	values []RuntimeCounter) (me.AttributeValueMap, error) {
	expected, err := runtimePerformanceHistory(instance)
	if err != nil {
		return nil, err
	}
	if len(values) != len(expected) {
		return nil, fmt.Errorf("history has %d counters, expected %d", len(values), len(expected))
	}
	result := make(me.AttributeValueMap, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value.Name]; duplicate {
			return nil, fmt.Errorf("duplicate history counter %s", value.Name)
		}
		seen[value.Name] = struct{}{}
		current, present := instance.Attributes[value.Name]
		if !present {
			return nil, fmt.Errorf("unknown history counter %s", value.Name)
		}
		converted, err := runtimeConvertUnsigned(current, value.Value)
		if err != nil {
			return nil, fmt.Errorf("history counter %s: %w", value.Name, err)
		}
		result[value.Name] = converted
	}
	for _, value := range expected {
		if _, present := seen[value.Name]; !present {
			return nil, fmt.Errorf("missing history counter %s", value.Name)
		}
	}
	return result, nil
}

func runtimeMIBFingerprint(snapshot []mib.Instance) (string, error) {
	filtered := make([]mib.Instance, 0, len(snapshot))
	for _, instance := range snapshot {
		attributes := make(me.AttributeValueMap)
		entity, omciErr := me.LoadManagedEntityDefinition(instance.ClassID,
			me.ParamData{EntityID: instance.EntityID})
		if omciErr.StatusCode() != me.Success {
			return "", omciErr.GetError()
		}
		definitions := entity.GetAttributeDefinitions()
		for name, value := range instance.Attributes {
			include := instance.ClassID == me.OnuGClassID &&
				(name == me.OnuG_VendorId || name == me.OnuG_SerialNumber)
			if !include && name != me.ManagedEntityID {
				definition, err := me.GetAttributeDefinitionByName(definitions, name)
				if err != nil {
					return "", err
				}
				include = me.SupportsAttributeAccess(*definition, me.Write) ||
					me.SupportsAttributeAccess(*definition, me.SetByCreate)
			}
			if include {
				attributes[name] = value
			}
		}
		filtered = append(filtered, mib.Instance{Key: instance.Key, Origin: instance.Origin,
			Attributes: attributes})
	}
	document, err := json.Marshal(filtered)
	if err != nil {
		return "", fmt.Errorf("encode runtime MIB fingerprint: %w", err)
	}
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:]), nil
}

func sortRuntimeState(state *RuntimeState) {
	sort.Slice(state.Alarms, func(i, j int) bool { return lessRuntimeKey(state.Alarms[i].Key, state.Alarms[j].Key) })
	sort.Slice(state.ARC, func(i, j int) bool { return lessRuntimeKey(state.ARC[i].Key, state.ARC[j].Key) })
	sort.Slice(state.BERSamples, func(i, j int) bool {
		return lessRuntimeKey(state.BERSamples[i].Key, state.BERSamples[j].Key)
	})
	sort.Slice(state.GEMPerformance, func(i, j int) bool {
		return lessRuntimeKey(state.GEMPerformance[i].Key, state.GEMPerformance[j].Key)
	})
	sort.Slice(state.FECPerformance, func(i, j int) bool {
		return lessRuntimeKey(state.FECPerformance[i].Key, state.FECPerformance[j].Key)
	})
	sort.Slice(state.EthernetPerformance, func(i, j int) bool {
		return lessRuntimeKey(state.EthernetPerformance[i].Key, state.EthernetPerformance[j].Key)
	})
	sort.Slice(state.XGSPerformance, func(i, j int) bool {
		return lessRuntimeKey(state.XGSPerformance[i].Key, state.XGSPerformance[j].Key)
	})
	sort.Slice(state.PerformanceTCA, func(i, j int) bool {
		return lessRuntimeKey(state.PerformanceTCA[i].Key, state.PerformanceTCA[j].Key)
	})
}

func lessRuntimeKey(left, right mib.Key) bool {
	return left.ClassID < right.ClassID ||
		(left.ClassID == right.ClassID && left.EntityID < right.EntityID)
}

func runtimeUnsigned(value interface{}) (uint64, bool) {
	switch typed := value.(type) {
	case uint8:
		return uint64(typed), true
	case uint16:
		return uint64(typed), true
	case uint32:
		return uint64(typed), true
	case uint64:
		return typed, true
	default:
		return 0, false
	}
}

func runtimeConvertUnsigned(current interface{}, value uint64) (interface{}, error) {
	switch current.(type) {
	case uint8:
		if value > 0xff {
			return nil, fmt.Errorf("value %d exceeds uint8", value)
		}
		return uint8(value), nil
	case uint16:
		if value > 0xffff {
			return nil, fmt.Errorf("value %d exceeds uint16", value)
		}
		return uint16(value), nil
	case uint32:
		if value > 0xffffffff {
			return nil, fmt.Errorf("value %d exceeds uint32", value)
		}
		return uint32(value), nil
	case uint64:
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported current type %T", current)
	}
}

func gemCountersAtLeast(current, baseline performance.GEMPortCounters) bool {
	return current.ReceivedGEMFrames >= baseline.ReceivedGEMFrames &&
		current.ReceivedPayloadBytes >= baseline.ReceivedPayloadBytes &&
		current.TransmittedGEMFrames >= baseline.TransmittedGEMFrames &&
		current.TransmittedPayloadBytes >= baseline.TransmittedPayloadBytes
}

func fecCountersAtLeast(current, baseline performance.FECCounters) bool {
	return current.CorrectedBytes >= baseline.CorrectedBytes &&
		current.CorrectedCodeWords >= baseline.CorrectedCodeWords &&
		current.UncorrectableCodeWords >= baseline.UncorrectableCodeWords &&
		current.TotalCodeWords >= baseline.TotalCodeWords &&
		current.FECSeconds >= baseline.FECSeconds
}

func xgsCountersAtLeast(current, baseline performance.XGSPONCounters) bool {
	currentValues := xgsCounterValues(current)
	baselineValues := xgsCounterValues(baseline)
	for index := range currentValues {
		if currentValues[index] < baselineValues[index] {
			return false
		}
	}
	return true
}

func xgsCounterValues(value performance.XGSPONCounters) []uint64 {
	return []uint64{
		value.TC.PSBdHECErrors, value.TC.XGTCHECErrors, value.TC.UnknownProfiles,
		value.TC.TransmittedXGEMFrames, value.TC.FragmentXGEMFrames,
		value.TC.XGEMHECLostWords, value.TC.XGEMKeyErrors, value.TC.XGEMHECErrors,
		value.TC.TransmittedNonIdleBytes, value.TC.ReceivedNonIdleBytes,
		value.TC.LODSEvents, value.TC.LODSRestored, value.TC.ONUReactivationsByLODS,
		value.Downstream.PLOAMMICErrors, value.Downstream.PLOAMMessages,
		value.Downstream.ProfileMessages, value.Downstream.RangingTimeMessages,
		value.Downstream.DeactivateONUIDMessages, value.Downstream.DisableSerialNumberMessages,
		value.Downstream.RequestRegistrationMessages, value.Downstream.AssignAllocIDMessages,
		value.Downstream.KeyControlMessages, value.Downstream.SleepAllowMessages,
		value.Downstream.BaselineOMCIMessages, value.Downstream.ExtendedOMCIMessages,
		value.Downstream.AssignONUIDMessages, value.Downstream.OMCIMICErrors,
		value.Upstream.PLOAMMessages, value.Upstream.SerialNumberMessages,
		value.Upstream.RegistrationMessages, value.Upstream.KeyReportMessages,
		value.Upstream.AcknowledgeMessages, value.Upstream.SleepRequestMessages,
	}
}

func ethernetCountersAtLeast(current, baseline performance.EthernetCounters) bool {
	return ethernetDirectionAtLeast(current.Received, baseline.Received) &&
		ethernetDirectionAtLeast(current.Transmitted, baseline.Transmitted)
}

func ethernetDirectionAtLeast(current, baseline performance.EthernetDirectionCounters) bool {
	if current.Frames < baseline.Frames || current.Octets < baseline.Octets ||
		current.DropEvents < baseline.DropEvents || current.BroadcastFrames < baseline.BroadcastFrames ||
		current.MulticastFrames < baseline.MulticastFrames || current.CRCErrors < baseline.CRCErrors ||
		current.BufferOverflows < baseline.BufferOverflows || current.InternalErrors < baseline.InternalErrors ||
		current.UndersizeFrames < baseline.UndersizeFrames || current.Fragments < baseline.Fragments ||
		current.Jabbers < baseline.Jabbers || current.OversizeFrames < baseline.OversizeFrames {
		return false
	}
	for index := range current.SizeBuckets {
		if current.SizeBuckets[index] < baseline.SizeBuckets[index] {
			return false
		}
	}
	return true
}

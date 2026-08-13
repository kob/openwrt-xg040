// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sort"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
)

const (
	arcAttribute         = "Arc"
	arcIntervalAttribute = "ArcInterval"
)

// PollARC expires all problem-free NALM-QI timers and returns the mandatory
// ARC cancellation AVCs. It is intended to be called by the daemon ticker.
func (e *Engine) PollARC(device omci.DeviceIdent) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := validateDeviceIdentifier(device); err != nil {
		return nil, err
	}
	device = e.notificationDeviceLocked(device)
	keys := make([]mib.Key, 0, len(e.arcFreeSince))
	for key := range e.arcFreeSince {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ClassID == keys[j].ClassID {
			return keys[i].EntityID < keys[j].EntityID
		}
		return keys[i].ClassID < keys[j].ClassID
	})

	var frames [][]byte
	for _, key := range keys {
		generated, err := e.pollARCKeyLocked(key, device)
		if err != nil {
			return nil, err
		}
		frames = append(frames, generated...)
	}
	return frames, nil
}

func (e *Engine) pollARCKeyLocked(key mib.Key, device omci.DeviceIdent) ([][]byte, error) {
	enabled, interval, supported, err := e.arcConfigurationLocked(key)
	if err != nil {
		return nil, err
	}
	if !supported || !enabled {
		delete(e.arcFreeSince, key)
		return nil, nil
	}
	if e.arcGroupHasAlarmLocked(key) {
		delete(e.arcFreeSince, key)
		return nil, nil
	}

	now := e.now()
	since, started := e.arcFreeSince[key]
	if !started {
		e.arcFreeSince[key] = now
		since = now
	}
	if interval == 255 || now.Before(since.Add(time.Duration(interval)*time.Minute)) {
		return nil, nil
	}

	delete(e.arcFreeSince, key)
	return e.notifyAttributeChangeLocked(key, me.AttributeValueMap{
		arcAttribute: uint8(0),
	}, device)
}

func (e *Engine) arcEnabledLocked(key mib.Key) bool {
	owner, supported, err := e.arcOwnerLocked(key)
	if err != nil || !supported {
		return false
	}
	enabled, _, supported, err := e.arcConfigurationLocked(owner)
	return err == nil && supported && enabled
}

func (e *Engine) arcOwnerLocked(key mib.Key) (mib.Key, bool, error) {
	_, _, supported, err := e.arcConfigurationLocked(key)
	if err != nil || supported {
		return key, supported, err
	}

	var owner mib.Key
	switch {
	case isEthernetPerformanceClass(key.ClassID):
		entityID, resolveErr := e.resolveEthernetPerformanceUNILocked(key)
		if resolveErr != nil {
			return mib.Key{}, false, resolveErr
		}
		owner = mib.Key{
			ClassID:  me.PhysicalPathTerminationPointEthernetUniClassID,
			EntityID: entityID,
		}
	case key.ClassID == me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID:
		for _, instance := range e.mib.Snapshot() {
			if instance.ClassID != me.AniGClassID {
				continue
			}
			if owner != (mib.Key{}) {
				return key, false, nil
			}
			owner = instance.Key
		}
		if owner == (mib.Key{}) {
			return key, false, nil
		}
	case key.ClassID == me.FecPerformanceMonitoringHistoryDataClassID:
		owner = mib.Key{ClassID: me.AniGClassID, EntityID: key.EntityID}
		if !e.mib.Exists(owner) {
			return key, false, nil
		}
	default:
		return key, false, nil
	}

	_, _, supported, err = e.arcConfigurationLocked(owner)
	return owner, supported, err
}

func (e *Engine) arcGroupHasAlarmLocked(owner mib.Key) bool {
	for key, bitmap := range e.alarms {
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

func (e *Engine) arcConfigurationLocked(key mib.Key) (bool, uint8, bool, error) {
	entity, omciErr := me.LoadManagedEntityDefinition(key.ClassID, me.ParamData{EntityID: key.EntityID})
	if omciErr.StatusCode() != me.Success {
		return false, 0, false, omciErr.GetError()
	}
	definitions := entity.GetAttributeDefinitions()
	arcDefinition, arcErr := me.GetAttributeDefinitionByName(definitions, arcAttribute)
	intervalDefinition, intervalErr := me.GetAttributeDefinitionByName(definitions, arcIntervalAttribute)
	if arcErr != nil || intervalErr != nil {
		return false, 0, false, nil
	}
	instance, err := e.mib.Get(key, arcDefinition.Mask|intervalDefinition.Mask)
	if err != nil {
		return false, 0, true, err
	}
	arc, arcPresent := instance.Attributes[arcAttribute].(uint8)
	if !arcPresent {
		arc = 0
	}
	interval, intervalPresent := instance.Attributes[arcIntervalAttribute].(uint8)
	if !intervalPresent {
		interval = 0
	}
	return arc == 1, interval, true, nil
}

func (e *Engine) afterSetLocked(key mib.Key, attributes me.AttributeValueMap,
	device omci.DeviceIdent) ([][]byte, error) {
	_, arcChanged := attributes[arcAttribute]
	_, intervalChanged := attributes[arcIntervalAttribute]
	if arcChanged || intervalChanged {
		enabled, _, supported, err := e.arcConfigurationLocked(key)
		if err != nil {
			return nil, err
		}
		if supported && enabled {
			if !e.arcGroupHasAlarmLocked(key) {
				if _, started := e.arcFreeSince[key]; !started {
					e.arcFreeSince[key] = e.now()
				}
			} else {
				delete(e.arcFreeSince, key)
			}
		} else {
			delete(e.arcFreeSince, key)
		}
	}

	var frames [][]byte
	if sample, present := e.opticalSample[key]; present && opticalConfigurationChanged(attributes) {
		generated, err := e.evaluateOpticalSampleLocked(key, sample, device)
		if err != nil {
			return nil, err
		}
		frames = append(frames, generated...)
	}
	if sample, present := e.berSample[key]; present && berConfigurationChanged(attributes) {
		generated, err := e.evaluateBERSampleLocked(key, sample, device)
		if err != nil {
			return nil, err
		}
		frames = append(frames, generated...)
	}
	if arcChanged || intervalChanged {
		generated, err := e.pollARCKeyLocked(key, device)
		if err != nil {
			return nil, err
		}
		frames = append(frames, generated...)
	}
	return frames, nil
}

func berConfigurationChanged(attributes me.AttributeValueMap) bool {
	_, sf := attributes[me.AniG_SignalFailThreshold]
	_, sd := attributes[me.AniG_SignalDegradeThreshold]
	return sf || sd
}

func opticalConfigurationChanged(attributes me.AttributeValueMap) bool {
	for _, name := range []string{
		me.AniG_LowerOpticalThreshold,
		me.AniG_UpperOpticalThreshold,
		me.AniG_LowerTransmitPowerThreshold,
		me.AniG_UpperTransmitPowerThreshold,
		arcAttribute,
		arcIntervalAttribute,
	} {
		if _, present := attributes[name]; present {
			return true
		}
	}
	return false
}

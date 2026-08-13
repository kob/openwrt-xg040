// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/optical"
)

const (
	aniLowReceiveAlarm    = uint8(0)
	aniHighReceiveAlarm   = uint8(1)
	aniSignalFailAlarm    = uint8(2)
	aniSignalDegradeAlarm = uint8(3)
	aniLowTransmitAlarm   = uint8(4)
	aniHighTransmitAlarm  = uint8(5)
	aniLaserBiasAlarm     = uint8(6)

	// The G.988 thresholds have 0.5 dB granularity. Use one code point as
	// hysteresis when the OLT supplies a threshold.
	opticalHysteresis = int32(250)

	// XG2010G EN7572/SFF-8472 alarm and warning thresholds. Warning values
	// form the clear boundary for the module's internal alarm policy.
	internalRXLowAlarm    = uint16(1)
	internalRXLowClear    = uint16(3)
	internalRXHighAlarm   = uint16(0x3124)
	internalRXHighClear   = uint16(0x2710)
	internalTXLowAlarm    = uint16(0)
	internalTXLowClear    = uint16(0)
	internalTXHighAlarm   = uint16(0xffff)
	internalTXHighClear   = uint16(0xffff)
	internalBiasHighAlarm = uint16(0xa605)
	internalBiasHighClear = uint16(0x9c40)
	gponDownstreamBitRate = uint64(2488320000)
)

type BERSample struct {
	Sequence   uint64 `json:"sequence"`
	BIPCount   uint32 `json:"bip_count"`
	IntervalMS uint32 `json:"interval_ms"`
	BootID     string `json:"boot_id"`
}

type aniOpticalConfiguration struct {
	lowerReceive  uint8
	upperReceive  uint8
	lowerTransmit uint8
	upperTransmit uint8
}

// NotifyOpticalSample updates the dynamic ANI-G attributes and evaluates all
// optical alarms from one coherent EN7572 diagnostics sample.
func (e *Engine) NotifyOpticalSample(key mib.Key, sample optical.Sample,
	device omci.DeviceIdent) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := validateDeviceIdentifier(device); err != nil {
		return nil, err
	}
	device = e.notificationDeviceLocked(device)
	if key.ClassID != me.AniGClassID {
		return nil, fmt.Errorf("optical sample target %v/%#x is not ANI-G", key.ClassID, key.EntityID)
	}
	e.opticalSample[key] = sample
	return e.evaluateOpticalSampleLocked(key, sample, device)
}

func (e *Engine) evaluateOpticalSampleLocked(key mib.Key, sample optical.Sample,
	device omci.DeviceIdent) ([][]byte, error) {
	levels := sample.ANI()
	frames, err := e.notifyAttributeChangeLocked(key, me.AttributeValueMap{
		me.AniG_OpticalSignalLevel:   levels.OpticalSignalLevel,
		me.AniG_TransmitOpticalLevel: levels.TransmitOpticalLevel,
	}, device)
	if err != nil {
		return nil, err
	}

	configuration, err := e.aniOpticalConfigurationLocked(key)
	if err != nil {
		return nil, err
	}
	bitmap := e.alarms[key]
	setAlarmCondition(&bitmap, aniLowReceiveAlarm,
		lowReceiveAlarm(alarmCondition(bitmap, aniLowReceiveAlarm), sample, levels, configuration.lowerReceive))
	setAlarmCondition(&bitmap, aniHighReceiveAlarm,
		highReceiveAlarm(alarmCondition(bitmap, aniHighReceiveAlarm), sample, levels, configuration.upperReceive))
	setAlarmCondition(&bitmap, aniLowTransmitAlarm,
		lowTransmitAlarm(alarmCondition(bitmap, aniLowTransmitAlarm), sample, levels, configuration.lowerTransmit))
	setAlarmCondition(&bitmap, aniHighTransmitAlarm,
		highTransmitAlarm(alarmCondition(bitmap, aniHighTransmitAlarm), sample, levels, configuration.upperTransmit))
	setAlarmCondition(&bitmap, aniLaserBiasAlarm,
		highRawAlarm(alarmCondition(bitmap, aniLaserBiasAlarm), sample.LaserBiasCurrent,
			internalBiasHighAlarm, internalBiasHighClear))

	frame, emitted, err := e.notifyAlarmLocked(key, bitmap, device)
	if err != nil {
		return nil, err
	}
	if emitted {
		frames = append(frames, frame)
	}
	return frames, nil
}

// NotifyBERSample evaluates the ANI-G SF and SD alarms from one OLT-defined
// BER interval. LOS and LOF are intentionally not accepted as substitutes.
func (e *Engine) NotifyBERSample(key mib.Key, sample BERSample,
	device omci.DeviceIdent) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := validateDeviceIdentifier(device); err != nil {
		return nil, err
	}
	device = e.notificationDeviceLocked(device)
	if key.ClassID != me.AniGClassID {
		return nil, fmt.Errorf("BER sample target %v/%#x is not ANI-G", key.ClassID, key.EntityID)
	}
	if err := validateBERSample(sample); err != nil {
		return nil, err
	}
	if previous, present := e.berSample[key]; present && sample.BootID == previous.BootID &&
		sample.Sequence <= previous.Sequence {
		return nil, fmt.Errorf("BER sample sequence %d is not newer than %d",
			sample.Sequence, previous.Sequence)
	}
	frames, err := e.evaluateBERSampleLocked(key, sample, device)
	if err != nil {
		return nil, err
	}
	e.berSample[key] = sample
	return frames, nil
}

func validateBERSample(sample BERSample) error {
	if sample.Sequence == 0 {
		return fmt.Errorf("BER sample sequence is zero")
	}
	if sample.IntervalMS == 0 {
		return fmt.Errorf("BER sample interval is zero")
	}
	if !validBootID(sample.BootID) {
		return fmt.Errorf("BER sample boot ID is invalid")
	}
	return nil
}

func validBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' ||
		value[18] != '-' || value[23] != '-' {
		return false
	}
	for index := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((value[index] >= '0' && value[index] <= '9') ||
			(value[index] >= 'a' && value[index] <= 'f') ||
			(value[index] >= 'A' && value[index] <= 'F')) {
			return false
		}
	}
	return true
}

func (e *Engine) evaluateBERSampleLocked(key mib.Key, sample BERSample,
	device omci.DeviceIdent) ([][]byte, error) {
	instance, err := e.mib.Get(key, 0x0600)
	if err != nil {
		return nil, err
	}
	sf, sfPresent := instance.Attributes[me.AniG_SignalFailThreshold].(uint8)
	sd, sdPresent := instance.Attributes[me.AniG_SignalDegradeThreshold].(uint8)
	if !sfPresent || !sdPresent {
		return nil, fmt.Errorf("ANI-G BER thresholds are missing")
	}

	bitmap := e.alarms[key]
	setAlarmCondition(&bitmap, aniSignalFailAlarm, berThresholdExceeded(sample, sf))
	setAlarmCondition(&bitmap, aniSignalDegradeAlarm, berThresholdExceeded(sample, sd))
	frame, emitted, err := e.notifyAlarmLocked(key, bitmap, device)
	if err != nil || !emitted {
		return nil, err
	}
	return [][]byte{frame}, nil
}

func berThresholdExceeded(sample BERSample, exponent uint8) bool {
	scale := uint64(1000)
	for i := uint8(0); i < exponent; i++ {
		scale *= 10
	}
	windowBits := gponDownstreamBitRate * uint64(sample.IntervalMS)
	minimumBIP := windowBits / scale
	if windowBits%scale != 0 {
		minimumBIP++
	}
	return uint64(sample.BIPCount) >= minimumBIP
}

func (e *Engine) aniOpticalConfigurationLocked(key mib.Key) (aniOpticalConfiguration, error) {
	mask := uint16(0x0033)
	instance, err := e.mib.Get(key, mask)
	if err != nil {
		return aniOpticalConfiguration{}, err
	}
	read := func(name string) (uint8, error) {
		value, present := instance.Attributes[name].(uint8)
		if !present {
			return 0, fmt.Errorf("ANI-G %s is missing", name)
		}
		return value, nil
	}
	var configuration aniOpticalConfiguration
	if configuration.lowerReceive, err = read(me.AniG_LowerOpticalThreshold); err != nil {
		return configuration, err
	}
	if configuration.upperReceive, err = read(me.AniG_UpperOpticalThreshold); err != nil {
		return configuration, err
	}
	if configuration.lowerTransmit, err = read(me.AniG_LowerTransmitPowerThreshold); err != nil {
		return configuration, err
	}
	if configuration.upperTransmit, err = read(me.AniG_UpperTransmitPowerThreshold); err != nil {
		return configuration, err
	}
	return configuration, nil
}

func lowReceiveAlarm(active bool, sample optical.Sample, levels optical.ANILevels, code uint8) bool {
	if code == 0xff {
		return lowRawAlarm(active, sample.ReceivePower, internalRXLowAlarm, internalRXLowClear)
	}
	return lowPowerAlarm(active, levels.ReceiveDBm, -int32(code)*250)
}

func highReceiveAlarm(active bool, sample optical.Sample, levels optical.ANILevels, code uint8) bool {
	if code == 0xff {
		return highRawAlarm(active, sample.ReceivePower, internalRXHighAlarm, internalRXHighClear)
	}
	return highPowerAlarm(active, levels.ReceiveDBm, -int32(code)*250)
}

func lowTransmitAlarm(active bool, sample optical.Sample, levels optical.ANILevels, code uint8) bool {
	if code == 0x81 {
		return lowRawAlarm(active, sample.TransmitPower, internalTXLowAlarm, internalTXLowClear)
	}
	return lowPowerAlarm(active, levels.TransmitDBm, int32(int8(code))*250)
}

func highTransmitAlarm(active bool, sample optical.Sample, levels optical.ANILevels, code uint8) bool {
	if code == 0x81 {
		return highRawAlarm(active, sample.TransmitPower, internalTXHighAlarm, internalTXHighClear)
	}
	return highPowerAlarm(active, levels.TransmitDBm, int32(int8(code))*250)
}

func lowPowerAlarm(active bool, value, threshold int32) bool {
	if active {
		return value < threshold+opticalHysteresis
	}
	return value < threshold
}

func highPowerAlarm(active bool, value, threshold int32) bool {
	if active {
		return value > threshold-opticalHysteresis
	}
	return value > threshold
}

func lowRawAlarm(active bool, value, alarm, clear uint16) bool {
	if active {
		return value < clear
	}
	return value < alarm
}

func highRawAlarm(active bool, value, alarm, clear uint16) bool {
	if active {
		return value > clear
	}
	return value > alarm
}

func alarmCondition(bitmap [28]byte, alarm uint8) bool {
	return bitmap[alarm/8]&(1<<uint(7-alarm%8)) != 0
}

func setAlarmCondition(bitmap *[28]byte, alarm uint8, active bool) {
	octet := alarm / 8
	bit := uint(7 - alarm%8)
	if active {
		bitmap[octet] |= 1 << bit
	} else {
		bitmap[octet] &^= 1 << bit
	}
}

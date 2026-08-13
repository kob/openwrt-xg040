// SPDX-License-Identifier: Apache-2.0

package optical

import "math"

// Sample is the SFF-8472 compatible EN7572 diagnostics block. Temperature is
// signed 1/256 C, voltage is 100 uV, bias is 2 uA and optical powers are 0.1 uW.
type Sample struct {
	Temperature      uint16 `json:"temperature"`
	SupplyVoltage    uint16 `json:"supply_voltage"`
	LaserBiasCurrent uint16 `json:"laser_bias_current"`
	TransmitPower    uint16 `json:"transmit_power"`
	ReceivePower     uint16 `json:"receive_power"`
}

// Diagnostics contains the five G.988 optical-line-supervision result values.
type Diagnostics struct {
	PowerFeedVoltage     uint16
	ReceivedOpticalPower uint16
	MeanOpticalLaunch    uint16
	LaserBiasCurrent     uint16
	Temperature          uint16
}

// ANILevels contains the ANI-G optical attributes and the corresponding
// signed power values in G.988 0.002 dB units. The attributes are encoded as
// two's-complement uint16 values for omci-lib-go.
type ANILevels struct {
	OpticalSignalLevel   uint16
	TransmitOpticalLevel uint16
	ReceiveDBm           int32
	TransmitDBm          int32
}

func (sample Sample) OMCI() Diagnostics {
	return Diagnostics{
		PowerFeedVoltage:     uint16((uint32(sample.SupplyVoltage) + 100) / 200),
		ReceivedOpticalPower: opticalPower(sample.ReceivePower),
		MeanOpticalLaunch:    opticalPower(sample.TransmitPower),
		LaserBiasCurrent:     sample.LaserBiasCurrent,
		Temperature:          sample.Temperature,
	}
}

// ANI converts the SFF-8472 power samples to the ANI-G 1 mW reference. A zero
// raw value represents power below the measurable range and is retained as a
// value below every configurable G.988 threshold for alarm evaluation.
func (sample Sample) ANI() ANILevels {
	receive := opticalPowerDBm(sample.ReceivePower)
	transmit := opticalPowerDBm(sample.TransmitPower)
	return ANILevels{
		OpticalSignalLevel:   signed16(receive),
		TransmitOpticalLevel: signed16(transmit),
		ReceiveDBm:           receive,
		TransmitDBm:          transmit,
	}
}

// G.988 encodes optical power as signed dBu with 0.002 dB resolution. The
// EN7572 uses unsigned 0.1 uW units, so zero is saturated at the lowest value.
func opticalPower(raw uint16) uint16 {
	if raw == 0 {
		return uint16(0x8000)
	}
	value := math.Round(5000 * (math.Log10(float64(raw)) - 1))
	if value < math.MinInt16 {
		value = math.MinInt16
	} else if value > math.MaxInt16 {
		value = math.MaxInt16
	}
	return uint16(int16(value))
}

func opticalPowerDBm(raw uint16) int32 {
	if raw == 0 {
		return math.MinInt32
	}
	// A raw unit is 0.1 uW. Therefore raw 10000 is 1 mW (0 dBm).
	return int32(math.Round(5000 * (math.Log10(float64(raw)) - 4)))
}

func signed16(value int32) uint16 {
	if value < math.MinInt16 {
		value = math.MinInt16
	} else if value > math.MaxInt16 {
		value = math.MaxInt16
	}
	return uint16(int16(value))
}

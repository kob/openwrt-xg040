// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/engine"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/optical"
)

type Event struct {
	Type             string                     `json:"type"`
	ClassID          me.ClassID                 `json:"class_id"`
	EntityID         uint16                     `json:"entity_id"`
	Format           string                     `json:"format,omitempty"`
	AlarmBit         *uint8                     `json:"alarm_bit,omitempty"`
	Active           *bool                      `json:"active,omitempty"`
	Attributes       map[string]json.RawMessage `json:"attributes,omitempty"`
	TransactionID    uint16                     `json:"transaction_id,omitempty"`
	Payload          string                     `json:"payload,omitempty"`
	Temperature      *uint16                    `json:"temperature,omitempty"`
	SupplyVoltage    *uint16                    `json:"supply_voltage,omitempty"`
	LaserBiasCurrent *uint16                    `json:"laser_bias_current,omitempty"`
	TransmitPower    *uint16                    `json:"transmit_power,omitempty"`
	ReceivePower     *uint16                    `json:"receive_power,omitempty"`
	Sequence         *uint64                    `json:"sequence,omitempty"`
	BIPCount         *uint32                    `json:"bip_count,omitempty"`
	IntervalMS       *uint32                    `json:"interval_ms,omitempty"`
	BootID           *string                    `json:"boot_id,omitempty"`
}

func Decode(line []byte) (Event, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var value Event
	if err := decoder.Decode(&value); err != nil {
		return Event{}, fmt.Errorf("decode platform event: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Event{}, fmt.Errorf("decode platform event: trailing JSON value")
		}
		return Event{}, fmt.Errorf("decode platform event: %w", err)
	}
	if value.Type == "" {
		return Event{}, fmt.Errorf("platform event type is empty")
	}
	return value, nil
}

func (event Event) Dispatch(protocol *engine.Engine) ([][]byte, error) {
	device, err := event.deviceIdentifier()
	if err != nil {
		return nil, err
	}
	key := mib.Key{ClassID: event.ClassID, EntityID: event.EntityID}

	switch event.Type {
	case "omcc-session-reset":
		protocol.ResetCommunicationSession()
		return nil, nil

	case "alarm":
		if event.AlarmBit == nil || event.Active == nil {
			return nil, fmt.Errorf("alarm event requires alarm_bit and active")
		}
		frame, changed, err := protocol.NotifyAlarmBit(key, *event.AlarmBit, *event.Active, device)
		if err != nil || !changed {
			return nil, err
		}
		return [][]byte{frame}, nil

	case "avc":
		attributes, err := event.decodeAttributes()
		if err != nil {
			return nil, err
		}
		return protocol.NotifyAttributeChange(key, attributes, device)

	case "test-result":
		payload, err := decodeHex(event.Payload)
		if err != nil {
			return nil, fmt.Errorf("decode test result payload: %w", err)
		}
		frame, err := protocol.TestResult(event.TransactionID, key, payload, device)
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil

	case "optical-sample":
		if event.Temperature == nil || event.SupplyVoltage == nil ||
			event.LaserBiasCurrent == nil || event.TransmitPower == nil || event.ReceivePower == nil {
			return nil, fmt.Errorf("optical sample requires all five diagnostics fields")
		}
		return protocol.NotifyOpticalSample(key, optical.Sample{
			Temperature:      *event.Temperature,
			SupplyVoltage:    *event.SupplyVoltage,
			LaserBiasCurrent: *event.LaserBiasCurrent,
			TransmitPower:    *event.TransmitPower,
			ReceivePower:     *event.ReceivePower,
		}, device)

	case "ber-sample":
		if event.Sequence == nil || event.BIPCount == nil || event.IntervalMS == nil ||
			event.BootID == nil {
			return nil, fmt.Errorf("BER sample requires sequence, bip_count, interval_ms and boot_id")
		}
		return protocol.NotifyBERSample(key, engine.BERSample{
			Sequence:   *event.Sequence,
			BIPCount:   *event.BIPCount,
			IntervalMS: *event.IntervalMS,
			BootID:     *event.BootID,
		}, device)

	default:
		return nil, fmt.Errorf("unsupported platform event type %q", event.Type)
	}
}

func (event Event) deviceIdentifier() (omci.DeviceIdent, error) {
	switch strings.ToLower(event.Format) {
	case "", "baseline":
		return omci.BaselineIdent, nil
	case "extended":
		return omci.ExtendedIdent, nil
	default:
		return 0, fmt.Errorf("unsupported platform event format %q", event.Format)
	}
}

func (event Event) decodeAttributes() (me.AttributeValueMap, error) {
	if len(event.Attributes) == 0 {
		return nil, fmt.Errorf("AVC event has no attributes")
	}
	entity, omciErr := me.LoadManagedEntityDefinition(event.ClassID,
		me.ParamData{EntityID: event.EntityID})
	if omciErr.StatusCode() != me.Success {
		return nil, omciErr.GetError()
	}
	definitions := entity.GetAttributeDefinitions()
	attributes := make(me.AttributeValueMap, len(event.Attributes))
	for name, raw := range event.Attributes {
		definition, err := me.GetAttributeDefinitionByName(definitions, name)
		if err != nil || definition.GetIndex() == 0 {
			return nil, fmt.Errorf("AVC attribute %q is not defined for class %d", name, event.ClassID)
		}
		value, err := decodeAttribute(*definition, raw)
		if err != nil {
			return nil, fmt.Errorf("decode AVC attribute %s: %w", definition.GetName(), err)
		}
		attributes[definition.GetName()] = value
	}
	return attributes, nil
}

func decodeAttribute(definition me.AttributeDefinition, raw json.RawMessage) (interface{}, error) {
	if definition.IsTableAttribute() {
		return nil, fmt.Errorf("table attributes are not accepted from the event stream")
	}
	var number json.Number
	if len(raw) != 0 && raw[0] != '"' && raw[0] != '[' {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&number); err == nil {
			var value uint64
			if definition.AttributeType == me.SignedIntegerAttributeType {
				signed, err := strconv.ParseInt(string(number), 10, definition.GetSize()*8)
				if err != nil {
					return nil, err
				}
				value = uint64(signed)
			} else {
				unsigned, err := strconv.ParseUint(string(number), 10, definition.GetSize()*8)
				if err != nil {
					return nil, err
				}
				value = unsigned
			}
			switch definition.GetSize() {
			case 1:
				return uint8(value), nil
			case 2:
				return uint16(value), nil
			case 4:
				return uint32(value), nil
			case 8:
				return uint64(value), nil
			default:
				return nil, fmt.Errorf("numeric value has unsupported size %d", definition.GetSize())
			}
		}
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		var value []byte
		var err error
		if strings.HasPrefix(text, "hex:") {
			value, err = decodeHex(strings.TrimPrefix(text, "hex:"))
		} else {
			value = []byte(text)
		}
		if err != nil {
			return nil, err
		}
		if len(value) > definition.GetSize() {
			return nil, fmt.Errorf("value has %d bytes, maximum is %d", len(value), definition.GetSize())
		}
		padded := make([]byte, definition.GetSize())
		copy(padded, value)
		return padded, nil
	}

	var octets []uint8
	if err := json.Unmarshal(raw, &octets); err != nil {
		return nil, fmt.Errorf("expected an unsigned integer, string, or byte array")
	}
	if len(octets) != definition.GetSize() {
		return nil, fmt.Errorf("byte array has %d bytes, expected %d", len(octets), definition.GetSize())
	}
	return []byte(octets), nil
}

func decodeHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("hex value has odd length")
	}
	return hex.DecodeString(value)
}

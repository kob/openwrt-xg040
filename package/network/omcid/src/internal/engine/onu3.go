// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"math/bits"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/onu3"
)

const onu3SnapshotStateMask = 0x3d00

func (e *Engine) setONU3Locked(key mib.Key, attributes me.AttributeValueMap) (me.AttributeValueMap, error) {
	if key.EntityID != 0 || !e.mib.Exists(key) {
		return nil, &mib.ResultError{Result: me.UnknownInstance}
	}

	snap := false
	reset := false
	for name, value := range attributes {
		switch name {
		case me.ManagedEntityID:
			continue
		case me.Onu3G_SnapAction:
			if _, valid := value.(uint8); !valid {
				return nil, &mib.ResultError{Result: me.ParameterError,
					Cause: fmt.Errorf("ONU3-G Snap action has type %T", value)}
			}
			snap = true
		case me.Onu3G_ResetAction:
			if _, valid := value.(uint8); !valid {
				return nil, &mib.ResultError{Result: me.ParameterError,
					Cause: fmt.Errorf("ONU3-G Reset action has type %T", value)}
			}
			reset = true
		default:
			return nil, &mib.ResultError{Result: me.AttributeFailure,
				UnsupportedMask: onu3AttributeMask(name)}
		}
	}
	if snap == reset {
		return nil, &mib.ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G Set requires exactly one action")}
	}

	current, err := e.mib.Get(key, onu3SnapshotStateMask)
	if err != nil {
		return nil, err
	}
	previousValid := current.Attributes[me.Onu3G_NumberOfValidStatusSnapshots].(uint16)
	previousNext := current.Attributes[me.Onu3G_NextStatusSnapshotIndex].(uint16)
	updates := make(me.AttributeValueMap)
	if reset {
		updates[me.Onu3G_NumberOfValidStatusSnapshots] = uint16(0)
		updates[me.Onu3G_NextStatusSnapshotIndex] = uint16(0)
		updates[me.Onu3G_StatusSnapshotRecordTable] = me.TableRows{}
		updates[me.Onu3G_MostRecentStatusSnapshot] = make([]byte, onu3.RecordSize)
	} else {
		total := current.Attributes[me.Onu3G_TotalNumberOfStatusSnapshots].(uint16)
		table := current.Attributes[me.Onu3G_StatusSnapshotRecordTable].(me.TableRows)
		record := (onu3.Record{
			Trigger:      onu3.TriggerOLTSnap,
			TakenAt:      e.now(),
			MIBDataSync:  e.mib.DataSync(),
			MIBEntries:   saturatingUint16(uint64(len(e.mib.Snapshot()))),
			ActiveAlarms: e.activeAlarmCountLocked(),
			ExtendedOMCI: e.extendedSeen,
		}).Encode()
		rows := append([]byte(nil), table.Rows...)
		valid := previousValid
		if valid < total {
			rows = append(rows, record[:]...)
			valid++
		} else {
			offset := int(previousNext) * onu3.RecordSize
			copy(rows[offset:offset+onu3.RecordSize], record[:])
		}
		next := (previousNext + 1) % total
		updates[me.Onu3G_NumberOfValidStatusSnapshots] = valid
		updates[me.Onu3G_NextStatusSnapshotIndex] = next
		updates[me.Onu3G_StatusSnapshotRecordTable] = me.TableRows{
			NumRows: int(valid), Rows: rows,
		}
		updates[me.Onu3G_MostRecentStatusSnapshot] = append([]byte(nil), record[:]...)
	}
	if err := e.mib.UpdateByCommand(map[mib.Key]me.AttributeValueMap{key: updates}); err != nil {
		return nil, err
	}

	changed := make(me.AttributeValueMap)
	if value := updates[me.Onu3G_NumberOfValidStatusSnapshots].(uint16); value != previousValid {
		changed[me.Onu3G_NumberOfValidStatusSnapshots] = value
	}
	if value := updates[me.Onu3G_NextStatusSnapshotIndex].(uint16); value != previousNext {
		changed[me.Onu3G_NextStatusSnapshotIndex] = value
	}
	return changed, nil
}

func (e *Engine) activeAlarmCountLocked() uint16 {
	count := 0
	for _, bitmap := range e.alarms {
		for _, octet := range bitmap {
			count += bits.OnesCount8(octet)
		}
	}
	return saturatingUint16(uint64(count))
}

func onu3AttributeMask(name string) uint16 {
	definitions, omciErr := me.GetAttributesDefinitions(me.Onu3GClassID)
	if omciErr.StatusCode() != me.Success {
		return 0xffff
	}
	definition, err := me.GetAttributeDefinitionByName(definitions, name)
	if err != nil {
		return 0xffff
	}
	return definition.Mask
}

// SPDX-License-Identifier: Apache-2.0

package mib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"reflect"
	"sort"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/vlan"
)

const (
	extendedVLANRowSize         = 16
	enhancedExtendedVLANRowSize = 28
	multicastIPv4RowSize        = 12
	multicastIPv6RowSize        = 24
	multicastACLRowSize         = 24
	multicastServiceRowSize     = 20
	multicastPreviewRowSize     = 22

	tableSetControlMask = uint16(0xc000)
	tableRowPartMask    = uint16(0x3800)
	tableTestMask       = uint16(0x0400)
	tableRowKeyMask     = uint16(0x03ff)
)

// AllowedPreviewTimer identifies the live ONU-owned timer for one logical
// class-310 allowed-preview row.
type AllowedPreviewTimer struct {
	RowKey   uint16
	Duration uint16
	TimeLeft uint16
}

var extendedVLANDefaultRows = []byte{
	0xf8, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00,
	0xf8, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00,
	0xe8, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00,
}

func initializeCreatedInstance(instance *Instance, extendedVLANTableSize uint16) {
	switch instance.ClassID {
	case me.ExtendedVlanTaggingOperationConfigurationDataClassID:
		instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize] = extendedVLANTableSize
		instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable] = me.TableRows{
			NumRows: 3,
			Rows:    append([]byte(nil), extendedVLANDefaultRows...),
		}
		instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable] = me.TableRows{}
	case me.MulticastGemInterworkingTerminationPointClassID:
		instance.Attributes[me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable] = me.TableRows{}
		instance.Attributes[me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable] = me.TableRows{}
	case me.MulticastOperationsProfileClassID:
		instance.Attributes[me.MulticastOperationsProfile_DynamicAccessControlListTable] = me.TableRows{}
		instance.Attributes[me.MulticastOperationsProfile_StaticAccessControlListTable] = me.TableRows{}
		instance.Attributes[me.MulticastOperationsProfile_LostGroupsListTable] = me.TableRows{}
	case me.MulticastSubscriberConfigInfoClassID:
		instance.Attributes[me.MulticastSubscriberConfigInfo_MulticastServicePackageTable] = me.TableRows{}
		instance.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable] = me.TableRows{}
	case me.MulticastSubscriberMonitorClassID:
		instance.Attributes[me.MulticastSubscriberMonitor_Ipv4ActiveGroupListTable] = me.TableRows{}
		instance.Attributes[me.MulticastSubscriberMonitor_Ipv6ActiveGroupListTable] = me.TableRows{}
	}
}

// SetTable applies one complete extended-message SetTable request. The
// candidate table and the full MIB snapshot reach the platform before either
// the table or MIB data sync is committed.
func (s *Store) SetTable(key Key, mask uint16, attributes me.AttributeValueMap) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.current[key]
	if !exists {
		return s.unknownKeyError(key)
	}
	entity, result := loadDefinition(key.ClassID, key.EntityID, current.Attributes)
	if result != nil {
		return result
	}
	if !me.SupportsMsgType(entity, me.SetTable) {
		return &ResultError{Result: me.NotSupported}
	}
	if supported, explicit := s.supportedAttributeMask(key.ClassID); explicit && mask&^supported != 0 {
		return &ResultError{Result: me.AttributeFailure, UnsupportedMask: mask &^ supported}
	}
	if bits.OnesCount16(mask) != 1 {
		return &ResultError{Result: me.ParameterError, Cause: fmt.Errorf("SetTable mask %#x does not select one attribute", mask)}
	}

	var definition *me.AttributeDefinition
	for index, candidate := range entity.GetAttributeDefinitions() {
		if index != 0 && candidate.Mask == mask {
			copy := candidate
			definition = &copy
			break
		}
	}
	if definition == nil || !definition.IsTableAttribute() ||
		!me.SupportsAttributeAccess(*definition, me.Write) {
		return &ResultError{Result: me.AttributeFailure, FailedMask: mask}
	}
	if len(attributes) != 1 && !(len(attributes) == 2 && attributes[me.ManagedEntityID] != nil) {
		return &ResultError{Result: me.ParameterError, Cause: fmt.Errorf("SetTable requires exactly one table attribute")}
	}
	value, present := attributes[definition.GetName()]
	if !present {
		return &ResultError{Result: me.AttributeFailure, FailedMask: mask}
	}
	updates, ok := value.(me.TableRows)
	if !ok || updates.NumRows < 0 || len(updates.Rows) != updates.NumRows*definition.GetSize() {
		return &ResultError{Result: me.ParameterError, Cause: fmt.Errorf("invalid %s row data", definition.GetName())}
	}

	existing, err := tableRows(current.Attributes[definition.GetName()], definition.GetSize())
	if err != nil {
		return &ResultError{Result: me.ProcessingError, Cause: err}
	}
	updated, err := s.applyTableRows(key.ClassID, definition.GetName(), existing, updates)
	if err != nil {
		return err
	}

	next := cloneInstance(current)
	next.Attributes[definition.GetName()] = updated
	normalized, err := s.normalize(next)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(current.Attributes, normalized.Attributes) {
		return nil
	}
	proposed := cloneInstances(s.current)
	proposed[key] = normalized
	return s.commitLocked(OperationSetTable, &current, &normalized, proposed, s.nextDataSyncLocked())
}

func (s *Store) applyTableRows(classID me.ClassID, name string, existing, updates me.TableRows) (me.TableRows, error) {
	switch classID {
	case me.MulticastGemInterworkingTerminationPointClassID:
		return applyMulticastAddressRows(name, existing, updates)
	case me.MulticastOperationsProfileClassID:
		return applyMulticastACLRows(name, existing, updates)
	case me.MulticastSubscriberConfigInfoClassID:
		return applyMulticastSubscriberRows(name, existing, updates)
	}
	if classID != me.ExtendedVlanTaggingOperationConfigurationDataClassID {
		return me.TableRows{}, &ResultError{Result: me.NotSupported,
			Cause: fmt.Errorf("SetTable policy for class %#x attribute %s is not implemented", classID, name)}
	}

	switch name {
	case me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable:
		for offset := 0; offset < len(updates.Rows); offset += extendedVLANRowSize {
			row := updates.Rows[offset : offset+extendedVLANRowSize]
			if allBytes(row[8:], 0xff) {
				continue
			}
			if _, err := vlan.ParseRow(row, false); err != nil {
				return me.TableRows{}, &ResultError{Result: me.ParameterError, Cause: err}
			}
		}
		rows := applyKeyedRows(existing.Rows, updates.Rows, extendedVLANRowSize, 8,
			func(row []byte) bool { return allBytes(row[8:], 0xff) })
		if len(rows)/extendedVLANRowSize > int(s.extendedVLANTableSize) {
			return me.TableRows{}, tableCapacityError(len(rows)/extendedVLANRowSize, s.extendedVLANTableSize)
		}
		return me.TableRows{NumRows: len(rows) / extendedVLANRowSize, Rows: rows}, nil

	case me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable:
		rows, err := applyEnhancedVLANRows(existing.Rows, updates.Rows)
		if err != nil {
			return me.TableRows{}, err
		}
		if len(rows)/enhancedExtendedVLANRowSize > int(s.extendedVLANTableSize) {
			return me.TableRows{}, tableCapacityError(len(rows)/enhancedExtendedVLANRowSize, s.extendedVLANTableSize)
		}
		return me.TableRows{NumRows: len(rows) / enhancedExtendedVLANRowSize, Rows: rows}, nil
	default:
		return me.TableRows{}, &ResultError{Result: me.NotSupported,
			Cause: fmt.Errorf("SetTable policy for class %#x attribute %s is not implemented", classID, name)}
	}
}

func applyMulticastAddressRows(name string, existing, updates me.TableRows) (me.TableRows, error) {
	rowSize := 0
	switch name {
	case me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable:
		rowSize = multicastIPv4RowSize
	case me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable:
		rowSize = multicastIPv6RowSize
	default:
		return me.TableRows{}, &ResultError{Result: me.NotSupported,
			Cause: fmt.Errorf("SetTable policy for class %#x attribute %s is not implemented",
				me.MulticastGemInterworkingTerminationPointClassID, name)}
	}

	for offset := 0; offset < len(updates.Rows); offset += rowSize {
		row := updates.Rows[offset : offset+rowSize]
		if allBytes(row[4:], 0) {
			continue
		}
		portID := binary.BigEndian.Uint16(row[0:2])
		if portID > 0x0fff {
			return me.TableRows{}, &ResultError{Result: me.ParameterError,
				Cause: fmt.Errorf("multicast address row has out-of-range GEM Port-ID %d", portID)}
		}
		if rowSize == multicastIPv4RowSize {
			start := binary.BigEndian.Uint32(row[4:8])
			stop := binary.BigEndian.Uint32(row[8:12])
			if start>>28 != 0xe || stop>>28 != 0xe || start > stop {
				return me.TableRows{}, &ResultError{Result: me.ParameterError,
					Cause: fmt.Errorf("invalid IPv4 multicast range %08x..%08x", start, stop)}
			}
		} else {
			start := binary.BigEndian.Uint32(row[4:8])
			stop := binary.BigEndian.Uint32(row[8:12])
			if row[12] != 0xff || start > stop {
				return me.TableRows{}, &ResultError{Result: me.ParameterError,
					Cause: fmt.Errorf("invalid IPv6 multicast range in row %x", row)}
			}
		}
	}

	rows := applyKeyedRows(existing.Rows, updates.Rows, rowSize, 4,
		func(row []byte) bool { return allBytes(row[4:], 0) })
	return me.TableRows{NumRows: len(rows) / rowSize, Rows: rows}, nil
}

type multicastACLRowKey struct {
	key  uint16
	part uint8
}

type multicastACLRange struct {
	key   uint16
	ipv6  bool
	start [16]byte
	stop  [16]byte
}

func applyMulticastACLRows(name string, existing, updates me.TableRows) (me.TableRows, error) {
	isStatic := false
	switch name {
	case me.MulticastOperationsProfile_DynamicAccessControlListTable:
	case me.MulticastOperationsProfile_StaticAccessControlListTable:
		isStatic = true
	default:
		return me.TableRows{}, &ResultError{Result: me.NotSupported,
			Cause: fmt.Errorf("SetTable policy for class %#x attribute %s is not implemented",
				me.MulticastOperationsProfileClassID, name)}
	}

	rows := make(map[multicastACLRowKey][]byte,
		len(existing.Rows)/multicastACLRowSize+len(updates.Rows)/multicastACLRowSize)
	for offset := 0; offset < len(existing.Rows); offset += multicastACLRowSize {
		row := append([]byte(nil), existing.Rows[offset:offset+multicastACLRowSize]...)
		control := binary.BigEndian.Uint16(row[:2])
		part := uint8((control & tableRowPartMask) >> 11)
		if control&(tableSetControlMask|tableTestMask) != 0 || part > 2 {
			return me.TableRows{}, &ResultError{Result: me.ProcessingError,
				Cause: fmt.Errorf("committed multicast ACL table contains invalid control %#x", control)}
		}
		key := control & tableRowKeyMask
		if err := validateMulticastACLPart(key, part, row, isStatic); err != nil {
			return me.TableRows{}, &ResultError{Result: me.ProcessingError, Cause: err}
		}
		rows[multicastACLRowKey{key: key, part: part}] = row
	}

	for offset := 0; offset < len(updates.Rows); offset += multicastACLRowSize {
		row := updates.Rows[offset : offset+multicastACLRowSize]
		control := binary.BigEndian.Uint16(row[:2])
		setControl := (control & tableSetControlMask) >> 14
		key := control & tableRowKeyMask
		part := uint8((control & tableRowPartMask) >> 11)
		switch setControl {
		case 1:
			if part > 2 {
				return me.TableRows{}, multicastACLParameterError(key,
					fmt.Sprintf("uses reserved row part %d", part))
			}
			stored := append([]byte(nil), row...)
			binary.BigEndian.PutUint16(stored[:2], uint16(part)<<11|key)
			if err := validateMulticastACLPart(key, part, stored, isStatic); err != nil {
				return me.TableRows{}, err
			}
			rowKey := multicastACLRowKey{key: key, part: part}
			if !isStatic && part == 1 && binary.BigEndian.Uint16(stored[20:22]) == 255 {
				reset := uint16(0)
				if previous := rows[rowKey]; previous != nil {
					reset = binary.BigEndian.Uint16(previous[20:22])
				}
				binary.BigEndian.PutUint16(stored[20:22], reset)
			}
			rows[rowKey] = stored
		case 2:
			for candidate := range rows {
				if candidate.key == key {
					delete(rows, candidate)
				}
			}
		case 3:
			clear(rows)
		default:
			return me.TableRows{}, multicastACLParameterError(key, "uses reserved set control")
		}
	}

	if err := validateMulticastACLRows(rows); err != nil {
		return me.TableRows{}, err
	}
	keys := make([]multicastACLRowKey, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].key != keys[j].key {
			return keys[i].key < keys[j].key
		}
		return keys[i].part < keys[j].part
	})
	result := make([]byte, 0, len(rows)*multicastACLRowSize)
	for _, key := range keys {
		result = append(result, rows[key]...)
	}
	return me.TableRows{NumRows: len(rows), Rows: result}, nil
}

func validateMulticastACLPart(key uint16, part uint8, row []byte, isStatic bool) error {
	switch part {
	case 0:
		gemPortID := binary.BigEndian.Uint16(row[2:4])
		if gemPortID > 0x0fff {
			return multicastACLParameterError(key,
				fmt.Sprintf("has out-of-range GEM Port-ID %d", gemPortID))
		}
		vlanID := binary.BigEndian.Uint16(row[4:6])
		if vlanID == 4096 || vlanID > 4097 && vlanID != 0xffff {
			return multicastACLParameterError(key, fmt.Sprintf("has invalid ANI VLAN ID %d", vlanID))
		}
		if !allBytes(row[22:24], 0) {
			return multicastACLParameterError(key, "has non-zero reserved bytes in row part 0")
		}
	case 1:
		if !isStatic {
			reset := binary.BigEndian.Uint16(row[20:22])
			if reset > 24 && reset < 241 {
				return multicastACLParameterError(key,
					fmt.Sprintf("has reserved preview reset time %d", reset))
			}
		}
		if !allBytes(row[22:24], 0) {
			return multicastACLParameterError(key, "has non-zero reserved bytes in row part 1")
		}
	case 2:
		if !allBytes(row[14:24], 0) {
			return multicastACLParameterError(key, "has non-zero reserved bytes in row part 2")
		}
	}
	return nil
}

func validateMulticastACLRows(rows map[multicastACLRowKey][]byte) error {
	ranges := make([]multicastACLRange, 0, len(rows))
	for rowKey, part0 := range rows {
		if rowKey.part != 0 {
			continue
		}
		part2 := rows[multicastACLRowKey{key: rowKey.key, part: 2}]
		value, err := multicastACLAddressRange(rowKey.key, part0, part2)
		if err != nil {
			return err
		}
		for _, previous := range ranges {
			if previous.ipv6 != value.ipv6 || bytes.Compare(previous.stop[:], value.start[:]) < 0 ||
				bytes.Compare(value.stop[:], previous.start[:]) < 0 {
				continue
			}
			return multicastACLParameterError(rowKey.key,
				fmt.Sprintf("destination range overlaps row key %d", previous.key))
		}
		ranges = append(ranges, value)
	}
	return nil
}

func multicastACLAddressRange(key uint16, part0, part2 []byte) (multicastACLRange, error) {
	result := multicastACLRange{key: key}
	if part2 == nil || ipv4CompatiblePrefix(part2[2:14]) {
		copy(result.start[12:], part0[10:14])
		copy(result.stop[12:], part0[14:18])
		if result.start[12]>>4 != 0xe || result.stop[12]>>4 != 0xe ||
			bytes.Compare(result.start[:], result.stop[:]) > 0 {
			return multicastACLRange{}, multicastACLParameterError(key,
				fmt.Sprintf("has invalid IPv4 multicast range %x..%x", part0[10:14], part0[14:18]))
		}
		return result, nil
	}

	result.ipv6 = true
	copy(result.start[:12], part2[2:14])
	copy(result.stop[:12], part2[2:14])
	copy(result.start[12:], part0[10:14])
	copy(result.stop[12:], part0[14:18])
	if result.start[0] != 0xff || bytes.Compare(result.start[:], result.stop[:]) > 0 {
		return multicastACLRange{}, multicastACLParameterError(key,
			fmt.Sprintf("has invalid IPv6 multicast range %x..%x", result.start, result.stop))
	}
	return result, nil
}

func ipv4CompatiblePrefix(prefix []byte) bool {
	return allBytes(prefix[:10], 0) &&
		((prefix[10] == 0 && prefix[11] == 0) || (prefix[10] == 0xff && prefix[11] == 0xff))
}

func multicastACLParameterError(key uint16, detail string) error {
	return &ResultError{Result: me.ParameterError,
		Cause: fmt.Errorf("multicast ACL row key %d %s", key, detail)}
}

func applyMulticastSubscriberRows(name string, existing, updates me.TableRows) (me.TableRows, error) {
	switch name {
	case me.MulticastSubscriberConfigInfo_MulticastServicePackageTable:
		return applyMulticastServiceRows(existing.Rows, updates.Rows)
	case me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable:
		return applyAllowedPreviewRows(existing.Rows, updates.Rows)
	default:
		return me.TableRows{}, &ResultError{Result: me.NotSupported,
			Cause: fmt.Errorf("SetTable policy for class %#x attribute %s is not implemented",
				me.MulticastSubscriberConfigInfoClassID, name)}
	}
}

func applyMulticastServiceRows(existing, updates []byte) (me.TableRows, error) {
	rows := make(map[uint16][]byte, len(existing)/multicastServiceRowSize+len(updates)/multicastServiceRowSize)
	for offset := 0; offset < len(existing); offset += multicastServiceRowSize {
		row := append([]byte(nil), existing[offset:offset+multicastServiceRowSize]...)
		control := binary.BigEndian.Uint16(row[:2])
		if control&^tableRowKeyMask != 0 {
			return me.TableRows{}, &ResultError{Result: me.ProcessingError,
				Cause: fmt.Errorf("committed multicast service table contains invalid control %#x", control)}
		}
		key := control & tableRowKeyMask
		if err := validateMulticastServiceRow(key, row); err != nil {
			return me.TableRows{}, &ResultError{Result: me.ProcessingError, Cause: err}
		}
		rows[key] = row
	}
	for offset := 0; offset < len(updates); offset += multicastServiceRowSize {
		row := updates[offset : offset+multicastServiceRowSize]
		control := binary.BigEndian.Uint16(row[:2])
		setControl := (control & tableSetControlMask) >> 14
		key := control & tableRowKeyMask
		switch setControl {
		case 1:
			if control&0x3c00 != 0 {
				return me.TableRows{}, multicastSubscriberParameterError(key,
					"service row has non-zero reserved control bits")
			}
			stored := append([]byte(nil), row...)
			binary.BigEndian.PutUint16(stored[:2], key)
			if err := validateMulticastServiceRow(key, stored); err != nil {
				return me.TableRows{}, err
			}
			rows[key] = stored
		case 2:
			delete(rows, key)
		case 3:
			clear(rows)
		default:
			return me.TableRows{}, multicastSubscriberParameterError(key,
				"service row uses reserved set control")
		}
	}
	keys := make([]int, 0, len(rows))
	for key := range rows {
		keys = append(keys, int(key))
	}
	sort.Ints(keys)
	result := make([]byte, 0, len(rows)*multicastServiceRowSize)
	for _, key := range keys {
		result = append(result, rows[uint16(key)]...)
	}
	return me.TableRows{NumRows: len(rows), Rows: result}, nil
}

func validateMulticastServiceRow(key uint16, row []byte) error {
	vlanID := binary.BigEndian.Uint16(row[2:4])
	if vlanID > 4097 && vlanID != 0xffff {
		return multicastSubscriberParameterError(key,
			fmt.Sprintf("service row has invalid UNI VLAN ID %d", vlanID))
	}
	profile := binary.BigEndian.Uint16(row[10:12])
	if profile == 0 || profile == 0xffff {
		return multicastSubscriberParameterError(key,
			fmt.Sprintf("service row has reserved operations profile pointer %#x", profile))
	}
	if !allBytes(row[12:20], 0) {
		return multicastSubscriberParameterError(key, "service row has non-zero reserved bytes")
	}
	return nil
}

func applyAllowedPreviewRows(existing, updates []byte) (me.TableRows, error) {
	rows := make(map[multicastACLRowKey][]byte,
		len(existing)/multicastPreviewRowSize+len(updates)/multicastPreviewRowSize)
	for offset := 0; offset < len(existing); offset += multicastPreviewRowSize {
		row := append([]byte(nil), existing[offset:offset+multicastPreviewRowSize]...)
		control := binary.BigEndian.Uint16(row[:2])
		part := uint8((control & tableRowPartMask) >> 11)
		if control&(tableSetControlMask|tableTestMask) != 0 || part > 1 {
			return me.TableRows{}, &ResultError{Result: me.ProcessingError,
				Cause: fmt.Errorf("committed allowed-preview table contains invalid control %#x", control)}
		}
		key := control & tableRowKeyMask
		var err error
		if part == 0 {
			err = validateAllowedPreviewPart0(key, row)
		} else {
			err = validateAllowedPreviewPart1(key, row)
		}
		if err != nil {
			return me.TableRows{}, &ResultError{Result: me.ProcessingError, Cause: err}
		}
		rows[multicastACLRowKey{key: key, part: part}] = row
	}

	for offset := 0; offset < len(updates); offset += multicastPreviewRowSize {
		row := updates[offset : offset+multicastPreviewRowSize]
		control := binary.BigEndian.Uint16(row[:2])
		setControl := (control & tableSetControlMask) >> 14
		key := control & tableRowKeyMask
		part := uint8((control & tableRowPartMask) >> 11)
		switch setControl {
		case 1:
			if control&tableTestMask != 0 || part > 1 {
				return me.TableRows{}, multicastSubscriberParameterError(key,
					fmt.Sprintf("preview row has invalid row part/control %d/%#x", part, control))
			}
			stored := append([]byte(nil), row...)
			binary.BigEndian.PutUint16(stored[:2], uint16(part)<<11|key)
			rowKey := multicastACLRowKey{key: key, part: part}
			if part == 0 {
				if err := validateAllowedPreviewPart0(key, stored); err != nil {
					return me.TableRows{}, err
				}
			} else {
				if err := validateAllowedPreviewPart1(key, stored); err != nil {
					return me.TableRows{}, err
				}
				duration := binary.BigEndian.Uint16(stored[18:20])
				timeLeft := duration
				if previous := rows[rowKey]; previous != nil {
					oldDuration := binary.BigEndian.Uint16(previous[18:20])
					oldTimeLeft := binary.BigEndian.Uint16(previous[20:22])
					if oldDuration != 0 && duration != 0 {
						adjusted := int64(oldTimeLeft) + int64(duration) - int64(oldDuration)
						if adjusted < 0 {
							adjusted = 0
						}
						if adjusted > 0xffff {
							adjusted = 0xffff
						}
						timeLeft = uint16(adjusted)
					}
				}
				binary.BigEndian.PutUint16(stored[20:22], timeLeft)
				if duration != 0 && timeLeft == 0 {
					for candidate := range rows {
						if candidate.key == key {
							delete(rows, candidate)
						}
					}
					continue
				}
			}
			rows[rowKey] = stored
		case 2:
			for candidate := range rows {
				if candidate.key == key {
					delete(rows, candidate)
				}
			}
		case 3:
			clear(rows)
		default:
			return me.TableRows{}, multicastSubscriberParameterError(key,
				"preview row uses reserved set control")
		}
	}

	keys := make([]multicastACLRowKey, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].key != keys[j].key {
			return keys[i].key < keys[j].key
		}
		return keys[i].part < keys[j].part
	})
	result := make([]byte, 0, len(rows)*multicastPreviewRowSize)
	for _, key := range keys {
		result = append(result, rows[key]...)
	}
	return me.TableRows{NumRows: len(rows), Rows: result}, nil
}

// OverlayAllowedPreviewTimers returns a response snapshot with current
// time-left fields. It never changes the committed MIB; GetNext therefore sees
// a stable copy captured by the initiating Get request.
func OverlayAllowedPreviewTimers(instance Instance, timers []AllowedPreviewTimer) (Instance, error) {
	if instance.ClassID != me.MulticastSubscriberConfigInfoClassID {
		return Instance{}, fmt.Errorf("allowed-preview timers require class %d, got %d",
			me.MulticastSubscriberConfigInfoClassID, instance.ClassID)
	}
	value, exists := instance.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable]
	if !exists {
		return instance, nil
	}
	rows, err := tableRows(value, multicastPreviewRowSize)
	if err != nil {
		return Instance{}, err
	}
	indexed, err := indexAllowedPreviewTimers(timers)
	if err != nil {
		return Instance{}, err
	}
	for offset := 0; offset < len(rows.Rows); offset += multicastPreviewRowSize {
		row := rows.Rows[offset : offset+multicastPreviewRowSize]
		control := binary.BigEndian.Uint16(row[:2])
		if control&tableRowPartMask != 1<<11 {
			continue
		}
		timer, found := indexed[control&tableRowKeyMask]
		if !found || timer.Duration != binary.BigEndian.Uint16(row[18:20]) {
			continue
		}
		binary.BigEndian.PutUint16(row[20:22], timer.TimeLeft)
	}
	instance.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable] = rows
	return instance, nil
}

// ExpireAllowedPreviewRows removes every matching timed logical row, including
// all of its row parts. The platform receives the new desired graph before the
// MIB commits, but the MIB data-sync counter is intentionally unchanged because
// expiry is an ONU-originated transition defined by G.988.
func (s *Store) ExpireAllowedPreviewRows(key Key, timers []AllowedPreviewTimer) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if key.ClassID != me.MulticastSubscriberConfigInfoClassID {
		return false, fmt.Errorf("allowed-preview expiry requires class %d, got %d",
			me.MulticastSubscriberConfigInfoClassID, key.ClassID)
	}
	current, exists := s.current[key]
	if !exists {
		return false, unknownKeyError(key)
	}
	indexed, err := indexAllowedPreviewTimers(timers)
	if err != nil {
		return false, err
	}
	value := current.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable]
	rows, err := tableRows(value, multicastPreviewRowSize)
	if err != nil {
		return false, err
	}
	expired := make(map[uint16]struct{})
	for offset := 0; offset < len(rows.Rows); offset += multicastPreviewRowSize {
		row := rows.Rows[offset : offset+multicastPreviewRowSize]
		control := binary.BigEndian.Uint16(row[:2])
		if control&tableRowPartMask != 1<<11 {
			continue
		}
		key := control & tableRowKeyMask
		timer, found := indexed[key]
		duration := binary.BigEndian.Uint16(row[18:20])
		if found && duration != 0 && timer.Duration == duration && timer.TimeLeft == 0 {
			expired[key] = struct{}{}
		}
	}
	if len(expired) == 0 {
		return false, nil
	}
	kept := make([]byte, 0, len(rows.Rows))
	for offset := 0; offset < len(rows.Rows); offset += multicastPreviewRowSize {
		row := rows.Rows[offset : offset+multicastPreviewRowSize]
		if _, remove := expired[binary.BigEndian.Uint16(row[:2])&tableRowKeyMask]; !remove {
			kept = append(kept, row...)
		}
	}
	next := cloneInstance(current)
	next.Attributes[me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable] = me.TableRows{
		NumRows: len(kept) / multicastPreviewRowSize, Rows: kept,
	}
	normalized, err := s.normalize(next)
	if err != nil {
		return false, err
	}
	proposed := cloneInstances(s.current)
	proposed[key] = normalized
	if err := s.commitLocked(OperationAutonomous, &current, &normalized, proposed, s.dataSync); err != nil {
		return false, err
	}
	return true, nil
}

func indexAllowedPreviewTimers(timers []AllowedPreviewTimer) (map[uint16]AllowedPreviewTimer, error) {
	result := make(map[uint16]AllowedPreviewTimer, len(timers))
	for _, timer := range timers {
		if timer.RowKey > tableRowKeyMask ||
			(timer.Duration == 0 && timer.TimeLeft != 0) ||
			(timer.Duration != 0 && timer.TimeLeft > timer.Duration) {
			return nil, fmt.Errorf("invalid allowed-preview timer row %d duration/time-left %d/%d",
				timer.RowKey, timer.Duration, timer.TimeLeft)
		}
		if _, duplicate := result[timer.RowKey]; duplicate {
			return nil, fmt.Errorf("duplicate allowed-preview timer row %d", timer.RowKey)
		}
		result[timer.RowKey] = timer
	}
	return result, nil
}

func validateAllowedPreviewPart0(key uint16, row []byte) error {
	for _, offset := range []int{18, 20} {
		if vlanID := binary.BigEndian.Uint16(row[offset : offset+2]); vlanID > 4095 {
			return multicastSubscriberParameterError(key,
				fmt.Sprintf("preview row has invalid VLAN ID %d", vlanID))
		}
	}
	return validatePreviewAddress(key, "source", row[2:18], false)
}

func validateAllowedPreviewPart1(key uint16, row []byte) error {
	return validatePreviewAddress(key, "destination", row[2:18], true)
}

func validatePreviewAddress(key uint16, field string, value []byte, multicast bool) error {
	if allBytes(value, 0) && !multicast {
		return nil
	}
	ipv4 := allBytes(value[:12], 0)
	valid := false
	if ipv4 {
		valid = !multicast || value[12]>>4 == 0xe
	} else {
		valid = !multicast || value[0] == 0xff
	}
	if !valid {
		return multicastSubscriberParameterError(key,
			fmt.Sprintf("preview row has invalid %s IP address %x", field, value))
	}
	return nil
}

func multicastSubscriberParameterError(key uint16, detail string) error {
	return &ResultError{Result: me.ParameterError,
		Cause: fmt.Errorf("multicast subscriber row key %d %s", key, detail)}
}

func tableRows(value interface{}, rowSize int) (me.TableRows, error) {
	if value == nil {
		return me.TableRows{}, nil
	}
	rows, ok := value.(me.TableRows)
	if !ok || rows.NumRows < 0 || len(rows.Rows) != rows.NumRows*rowSize {
		return me.TableRows{}, fmt.Errorf("committed table has invalid row data")
	}
	return me.TableRows{NumRows: rows.NumRows, Rows: append([]byte(nil), rows.Rows...)}, nil
}

func applyKeyedRows(existing, updates []byte, rowSize, keySize int, deleted func([]byte) bool) []byte {
	rows := make(map[string][]byte, len(existing)/rowSize+len(updates)/rowSize)
	for offset := 0; offset < len(existing); offset += rowSize {
		row := existing[offset : offset+rowSize]
		rows[string(row[:keySize])] = append([]byte(nil), row...)
	}
	for offset := 0; offset < len(updates); offset += rowSize {
		row := updates[offset : offset+rowSize]
		key := string(row[:keySize])
		if deleted(row) {
			delete(rows, key)
		} else {
			rows[key] = append([]byte(nil), row...)
		}
	}
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]byte, 0, len(rows)*rowSize)
	for _, key := range keys {
		result = append(result, rows[key]...)
	}
	return result
}

func applyEnhancedVLANRows(existing, updates []byte) ([]byte, error) {
	rows := make(map[uint16][]byte, len(existing)/enhancedExtendedVLANRowSize)
	for offset := 0; offset < len(existing); offset += enhancedExtendedVLANRowSize {
		row := append([]byte(nil), existing[offset:offset+enhancedExtendedVLANRowSize]...)
		row[0] &= 0x3f
		rows[binary.BigEndian.Uint16(row[2:4])] = row
	}
	for offset := 0; offset < len(updates); offset += enhancedExtendedVLANRowSize {
		row := updates[offset : offset+enhancedExtendedVLANRowSize]
		control := row[0] >> 6
		key := binary.BigEndian.Uint16(row[2:4])
		switch control {
		case 1:
			if direction := (row[0] >> 4) & 0x03; direction == 3 {
				return nil, &ResultError{Result: me.ParameterError,
					Cause: fmt.Errorf("enhanced VLAN row %#x has reserved direction", key)}
			}
			stored := append([]byte(nil), row...)
			stored[0] &= 0x3f
			if _, err := vlan.ParseRow(stored, true); err != nil {
				return nil, &ResultError{Result: me.ParameterError, Cause: err}
			}
			rows[key] = stored
		case 2:
			delete(rows, key)
		case 3:
			clear(rows)
		default:
			return nil, &ResultError{Result: me.ParameterError,
				Cause: fmt.Errorf("enhanced VLAN row %#x has reserved set control", key)}
		}
	}
	keys := make([]int, 0, len(rows))
	for key := range rows {
		keys = append(keys, int(key))
	}
	sort.Ints(keys)
	result := make([]byte, 0, len(rows)*enhancedExtendedVLANRowSize)
	for _, key := range keys {
		result = append(result, rows[uint16(key)]...)
	}
	return result, nil
}

func allBytes(value []byte, expected byte) bool {
	return len(value) != 0 && bytes.Count(value, []byte{expected}) == len(value)
}

func tableCapacityError(rows int, capacity uint16) error {
	return &ResultError{Result: me.ProcessingError,
		Cause: fmt.Errorf("table has %d rows, maximum is %d", rows, capacity)}
}

// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"fmt"
	"sort"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
)

const capabilityAttributeIDShift = 5

var capabilityMessageTypes = []me.MsgType{
	me.Create,
	me.Delete,
	me.Set,
	me.Get,
	me.GetAllAlarms,
	me.GetAllAlarmsNext,
	me.MibUpload,
	me.MibUploadNext,
	me.MibReset,
	me.AlarmNotification,
	me.AttributeValueChange,
	me.Test,
	me.StartSoftwareDownload,
	me.DownloadSection,
	me.EndSoftwareDownload,
	me.ActivateSoftware,
	me.CommitSoftware,
	me.SynchronizeTime,
	me.Reboot,
	me.GetNext,
	me.TestResult,
	me.GetCurrentData,
	me.SetTable,
}

func isCapabilityClass(classID me.ClassID) bool {
	switch classID {
	case me.OmciClassID, me.ManagedEntityMeClassID, me.AttributeMeClassID:
		return true
	default:
		return false
	}
}

func (e *Engine) capabilityInstanceExistsLocked(key mib.Key) bool {
	if !isCapabilityClass(key.ClassID) {
		return false
	}
	classes := e.mib.SupportedClasses()
	if len(classes) == 0 || validateCapabilityClasses(classes) != nil {
		return false
	}
	_, err := e.capabilityInstanceLocked(key, classes)
	return err == nil
}

// getCapabilityLocked synthesizes classes 287-289 instead of persisting
// hundreds of static declaration objects in the ONU MIB and platform state.
func (e *Engine) getCapabilityLocked(key mib.Key, mask uint16) (mib.Instance, error, bool) {
	if !isCapabilityClass(key.ClassID) {
		return mib.Instance{}, nil, false
	}
	classes := e.mib.SupportedClasses()
	if len(classes) == 0 {
		return mib.Instance{}, nil, false
	}
	if err := validateCapabilityClasses(classes); err != nil {
		return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}, true
	}

	instance, err := e.capabilityInstanceLocked(key, classes)
	if err != nil {
		return mib.Instance{}, err, true
	}
	definition, omciErr := me.LoadManagedEntityDefinition(key.ClassID, me.ParamData{EntityID: key.EntityID})
	if omciErr.StatusCode() != me.Success {
		return mib.Instance{}, &mib.ResultError{Result: omciErr.StatusCode(), Cause: omciErr.GetError()}, true
	}
	allowed := definition.GetAllowedAttributeMask()
	unsupported := mask &^ allowed
	selected := me.AttributeValueMap{me.ManagedEntityID: key.EntityID}
	for index, attribute := range definition.GetAttributeDefinitions() {
		if index == 0 || mask&attribute.Mask == 0 {
			continue
		}
		if value, present := instance.Attributes[attribute.GetName()]; present {
			selected[attribute.GetName()] = value
		}
	}
	instance.Attributes = selected
	if unsupported != 0 {
		return instance, &mib.ResultError{
			Result: me.AttributeFailure, UnsupportedMask: unsupported,
		}, true
	}
	return instance, nil, true
}

func (e *Engine) capabilityInstanceLocked(key mib.Key, classes []me.ClassID) (mib.Instance, error) {
	attributes := me.AttributeValueMap{me.ManagedEntityID: key.EntityID}
	switch key.ClassID {
	case me.OmciClassID:
		if key.EntityID != 0 {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		classRows := make([]byte, len(classes)*2)
		for index, classID := range classes {
			binary.BigEndian.PutUint16(classRows[index*2:], uint16(classID))
		}
		messageRows := make([]byte, len(capabilityMessageTypes))
		for index, messageType := range capabilityMessageTypes {
			messageRows[index] = byte(messageType)
		}
		attributes[me.Omci_MeTypeTable] = tableValue(classRows, 2)
		attributes[me.Omci_MessageTypeTable] = tableValue(messageRows, 1)

	case me.ManagedEntityMeClassID:
		classID := me.ClassID(key.EntityID)
		if !classInSortedList(classes, classID) {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		definition, err := capabilityDefinition(classID)
		if err != nil {
			return mib.Instance{}, err
		}
		attributeDefinitions := e.capabilityAttributeDefinitionsLocked(classID, definition)
		attributeRows := make([]byte, len(attributeDefinitions)*2)
		for index, attribute := range attributeDefinitions {
			binary.BigEndian.PutUint16(attributeRows[index*2:],
				capabilityAttributeID(classID, attribute.GetIndex()))
		}
		attributes[me.ManagedEntityMe_Name] = fixedCapabilityName(definition.GetName())
		attributes[me.ManagedEntityMe_AttributesTable] = tableValue(attributeRows, 2)
		attributes[me.ManagedEntityMe_Access] = uint8(definition.Access)
		attributes[me.ManagedEntityMe_AlarmsTable] = tableValue(capabilityAlarmCodes(classID), 1)
		attributes[me.ManagedEntityMe_AvcsTable] = tableValue(capabilityAVCIndexes(classID), 1)
		attributes[me.ManagedEntityMe_Actions] = capabilityActions(classID, definition)
		attributes[me.ManagedEntityMe_InstancesTable] = tableValue(e.capabilityInstanceIDsLocked(classID, classes), 2)
		attributes[me.ManagedEntityMe_Support] = uint8(me.PartiallySupported)

	case me.AttributeMeClassID:
		classID, attributeIndex := decodeCapabilityAttributeID(key.EntityID)
		if !classInSortedList(classes, classID) {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		definition, err := capabilityDefinition(classID)
		if err != nil {
			return mib.Instance{}, err
		}
		var attribute *me.AttributeDefinition
		for _, candidate := range e.capabilityAttributeDefinitionsLocked(classID, definition) {
			if candidate.GetIndex() == attributeIndex {
				copy := candidate
				attribute = &copy
				break
			}
		}
		if attribute == nil {
			return mib.Instance{}, &mib.ResultError{Result: me.UnknownInstance}
		}
		lower, upper, bitField := capabilityAttributeBounds(*attribute)
		var codePoints []byte
		if capability, constrained := e.mib.AttributeCapability(classID, attribute.GetName()); constrained {
			lower, upper, bitField = capability.LowerLimit, capability.UpperLimit, capability.BitField
			codePoints = make([]byte, len(capability.CodePoints)*2)
			for index, value := range capability.CodePoints {
				binary.BigEndian.PutUint16(codePoints[index*2:], value)
			}
		}
		attributes[me.AttributeMe_Name] = fixedCapabilityName(attribute.GetName())
		attributes[me.AttributeMe_Size] = uint16(attribute.GetSize())
		attributes[me.AttributeMe_Access] = capabilityAttributeAccess(*attribute)
		attributes[me.AttributeMe_Format] = capabilityAttributeFormat(attribute.AttributeType)
		attributes[me.AttributeMe_LowerLimit] = lower
		attributes[me.AttributeMe_UpperLimit] = upper
		attributes[me.AttributeMe_BitField] = bitField
		attributes[me.AttributeMe_CodePointsTable] = tableValue(codePoints, 2)
		attributes[me.AttributeMe_Support] = uint8(me.PartiallySupported)
	}
	return mib.Instance{Key: key, Attributes: attributes, Origin: mib.OriginONU}, nil
}

func capabilityDefinition(classID me.ClassID) (*me.ManagedEntityDefinition, error) {
	entity, omciErr := me.LoadManagedEntityDefinition(classID, me.ParamData{EntityID: 0})
	if omciErr.StatusCode() != me.Success {
		return nil, &mib.ResultError{Result: me.UnknownEntity, Cause: omciErr.GetError()}
	}
	definition := entity.GetManagedEntityDefinition()
	return &definition, nil
}

func (e *Engine) capabilityAttributeDefinitionsLocked(classID me.ClassID,
	definition *me.ManagedEntityDefinition) []me.AttributeDefinition {
	supportedMask, explicit := e.mib.SupportedAttributeMask(classID)
	definitions := make([]me.AttributeDefinition, 0, len(definition.AttributeDefinitions)-1)
	for _, index := range me.GetAttributeDefinitionMapKeys(definition.AttributeDefinitions) {
		if index == 0 {
			continue
		}
		attribute := definition.AttributeDefinitions[index]
		if explicit && attribute.Mask&supportedMask == 0 {
			continue
		}
		definitions = append(definitions, attribute)
	}
	return definitions
}

func (e *Engine) capabilityInstanceIDsLocked(classID me.ClassID, classes []me.ClassID) []byte {
	var ids []uint16
	switch classID {
	case me.OmciClassID:
		ids = []uint16{0}
	case me.ManagedEntityMeClassID:
		ids = make([]uint16, len(classes))
		for index, candidate := range classes {
			ids[index] = uint16(candidate)
		}
	case me.AttributeMeClassID:
		for _, candidate := range classes {
			definition, err := capabilityDefinition(candidate)
			if err != nil {
				continue
			}
			for _, attribute := range e.capabilityAttributeDefinitionsLocked(candidate, definition) {
				ids = append(ids, capabilityAttributeID(candidate, attribute.GetIndex()))
			}
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	default:
		for _, instance := range e.mib.Snapshot() {
			if instance.ClassID == classID {
				ids = append(ids, instance.EntityID)
			}
		}
	}
	rows := make([]byte, len(ids)*2)
	for index, id := range ids {
		binary.BigEndian.PutUint16(rows[index*2:], id)
	}
	return rows
}

func capabilityActions(classID me.ClassID, definition *me.ManagedEntityDefinition) uint32 {
	var actions uint32
	for _, messageType := range capabilityMessageTypes {
		if messageType >= 32 || !definition.MessageTypes.Contains(messageType) ||
			!capabilityActionImplemented(classID, definition.Access, messageType) {
			continue
		}
		actions |= uint32(1) << uint(messageType)
	}
	return actions
}

func capabilityActionImplemented(classID me.ClassID, access me.ClassAccess, messageType me.MsgType) bool {
	switch messageType {
	case me.Create, me.Delete:
		return access == me.CreatedByOlt || access == me.CreatedByBoth
	case me.Test:
		return classID == me.AniGClassID
	case me.Reboot, me.SynchronizeTime:
		return classID == me.OnuGClassID
	case me.StartSoftwareDownload, me.DownloadSection, me.EndSoftwareDownload,
		me.ActivateSoftware, me.CommitSoftware:
		return classID == me.SoftwareImageClassID
	case me.GetAllAlarms, me.GetAllAlarmsNext, me.MibUpload, me.MibUploadNext, me.MibReset:
		return classID == me.OnuDataClassID
	case me.GetCurrentData:
		return isPerformanceClass(classID)
	case me.SetTable:
		switch classID {
		case me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			me.MulticastGemInterworkingTerminationPointClassID,
			me.MulticastOperationsProfileClassID,
			me.MulticastSubscriberConfigInfoClassID:
			return true
		default:
			return false
		}
	default:
		return true
	}
}

func capabilityAlarmCodes(classID me.ClassID) []byte {
	switch classID {
	case me.AniGClassID:
		return []byte{0, 1, 2, 3, 4, 5, 6}
	case me.PhysicalPathTerminationPointEthernetUniClassID:
		return []byte{0}
	}
	rules := performanceThresholdRules(classID)
	seen := make(map[uint8]struct{}, len(rules))
	result := make([]byte, 0, len(rules))
	for _, rule := range rules {
		if _, duplicate := seen[rule.alarm]; duplicate {
			continue
		}
		seen[rule.alarm] = struct{}{}
		result = append(result, rule.alarm)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func capabilityAVCIndexes(classID me.ClassID) []byte {
	switch classID {
	case me.OnuGClassID:
		return []byte{8}
	case me.AniGClassID:
		return []byte{8, 10, 14}
	case me.PhysicalPathTerminationPointEthernetUniClassID:
		return []byte{6, 12}
	case me.Onu3GClassID:
		return []byte{4, 5}
	default:
		return nil
	}
}

func capabilityAttributeID(classID me.ClassID, index uint) uint16 {
	return uint16(classID)<<capabilityAttributeIDShift | uint16(index)
}

func decodeCapabilityAttributeID(entityID uint16) (me.ClassID, uint) {
	return me.ClassID(entityID >> capabilityAttributeIDShift),
		uint(entityID & ((1 << capabilityAttributeIDShift) - 1))
}

func capabilityAttributeAccess(attribute me.AttributeDefinition) uint8 {
	var access uint8
	for _, candidate := range []me.AttributeAccess{me.Read, me.Write, me.SetByCreate} {
		if me.SupportsAttributeAccess(attribute, candidate) {
			access |= uint8(candidate)
		}
	}
	return access
}

func capabilityAttributeFormat(attributeType me.AttributeType) uint8 {
	switch attributeType {
	case me.PointerAttributeType:
		return 1
	case me.BitFieldAttributeType:
		return 2
	case me.SignedIntegerAttributeType:
		return 3
	case me.UnsignedIntegerAttributeType, me.CounterAttributeType:
		return 4
	case me.OctetsAttributeType, me.StringAttributeType, me.UnknownAttributeType:
		return 5
	case me.EnumerationAttributeType:
		return 6
	case me.TableAttributeType:
		return 7
	default:
		return 0
	}
}

func capabilityAttributeBounds(attribute me.AttributeDefinition) (uint32, uint32, uint32) {
	bits := attribute.GetSize() * 8
	if bits <= 0 || bits > 32 || attribute.IsTableAttribute() ||
		attribute.AttributeType == me.OctetsAttributeType ||
		attribute.AttributeType == me.StringAttributeType ||
		attribute.AttributeType == me.UnknownAttributeType {
		return 0, 0, 0
	}
	maximum := uint32(0xffffffff)
	if bits < 32 {
		maximum = uint32(1<<bits) - 1
	}
	if attribute.AttributeType == me.SignedIntegerAttributeType {
		upper := maximum >> 1
		lower := ^upper
		return lower, upper, 0
	}
	if attribute.AttributeType == me.BitFieldAttributeType {
		return 0, maximum, maximum
	}
	return 0, maximum, 0
}

func fixedCapabilityName(value string) []byte {
	result := make([]byte, 25)
	copy(result, value)
	return result
}

func tableValue(rows []byte, rowSize int) me.TableRows {
	return me.TableRows{NumRows: len(rows) / rowSize, Rows: append([]byte(nil), rows...)}
}

func classInSortedList(classes []me.ClassID, wanted me.ClassID) bool {
	index := sort.Search(len(classes), func(index int) bool { return classes[index] >= wanted })
	return index < len(classes) && classes[index] == wanted
}

func validateCapabilityClasses(classes []me.ClassID) error {
	for _, classID := range classes {
		if uint32(classID) >= 1<<(16-capabilityAttributeIDShift) {
			return fmt.Errorf("managed entity class %#x cannot be encoded in an Attribute ME ID", classID)
		}
	}
	return nil
}

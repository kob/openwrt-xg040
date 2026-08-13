// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"

	"github.com/google/gopacket"
	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
)

const baselineAVCPayloadLimit = 30

// NotifyAlarm updates the alarm audit table and returns an autonomous alarm
// notification when the bitmap changed. Alarm sequence numbers are shared by
// all managed entities, range from 1 through 255 and wrap back to 1.
func (e *Engine) NotifyAlarm(key mib.Key, bitmap [28]byte,
	device omci.DeviceIdent) ([]byte, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.notifyAlarmLocked(key, bitmap, device)
}

// NotifyAlarmBit changes one alarm condition without overwriting other active
// alarms for the same managed entity.
func (e *Engine) NotifyAlarmBit(key mib.Key, alarm uint8, active bool,
	device omci.DeviceIdent) ([]byte, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if alarm >= omci.AlarmBitmapSize {
		return nil, false, fmt.Errorf("alarm bit %d is outside the 224-bit bitmap", alarm)
	}
	bitmap := e.alarms[key]
	octet := alarm / 8
	bit := uint(7 - alarm%8)
	if active {
		bitmap[octet] |= 1 << bit
	} else {
		bitmap[octet] &^= 1 << bit
	}
	return e.notifyAlarmLocked(key, bitmap, device)
}

func (e *Engine) notifyAlarmLocked(key mib.Key, bitmap [28]byte,
	device omci.DeviceIdent) ([]byte, bool, error) {

	if err := validateDeviceIdentifier(device); err != nil {
		return nil, false, err
	}
	device = e.notificationDeviceLocked(device)
	if !e.mib.Exists(key) {
		return nil, false, fmt.Errorf("alarm target %v/%#x does not exist", key.ClassID, key.EntityID)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(key.ClassID, me.ParamData{EntityID: key.EntityID})
	if omciErr.StatusCode() != me.Success {
		return nil, false, omciErr.GetError()
	}
	if err := validateAlarmBitmap(entity.GetAlarmMap(), bitmap); err != nil {
		return nil, false, fmt.Errorf("alarm target %v/%#x: %w", key.ClassID, key.EntityID, err)
	}
	if err := e.validateCapabilityAlarmLocked(key.ClassID, bitmap); err != nil {
		return nil, false, fmt.Errorf("alarm target %v/%#x: %w", key.ClassID, key.EntityID, err)
	}
	previous, found := e.alarms[key]
	if found && previous == bitmap {
		return nil, false, nil
	}
	if !found && bitmap == ([28]byte{}) {
		return nil, false, nil
	}

	if bitmap == ([28]byte{}) {
		delete(e.alarms, key)
	} else {
		e.alarms[key] = bitmap
	}
	suppressed, err := e.notificationsSuppressedLocked(key)
	if err != nil {
		return nil, false, err
	}
	arcOwner, arcSupported, err := e.arcOwnerLocked(key)
	if err != nil {
		return nil, false, err
	}
	arcEnabled := false
	if arcSupported {
		arcEnabled, _, _, err = e.arcConfigurationLocked(arcOwner)
		if err != nil {
			return nil, false, err
		}
	}
	if arcEnabled {
		if e.arcGroupHasAlarmLocked(arcOwner) {
			delete(e.arcFreeSince, arcOwner)
		} else if _, exists := e.arcFreeSince[arcOwner]; !exists {
			e.arcFreeSince[arcOwner] = e.now()
		}
		frames, err := e.pollARCKeyLocked(arcOwner, device)
		if err != nil {
			return nil, false, err
		}
		if len(frames) == 0 {
			return nil, false, nil
		}
		if suppressed {
			return nil, false, nil
		}
		return frames[0], true, nil
	}
	if suppressed {
		return nil, false, nil
	}

	previousSequence := e.alarmSequence
	sequence := e.nextAlarmSequenceLocked()
	frame, err := serializeAutonomous(device, 0, omci.AlarmNotificationType,
		&omci.AlarmNotificationMsg{
			MeBasePacket: omci.MeBasePacket{
				EntityClass:    key.ClassID,
				EntityInstance: key.EntityID,
				Extended:       device == omci.ExtendedIdent,
			},
			AlarmBitmap:         bitmap,
			AlarmSequenceNumber: sequence,
		})
	if err != nil {
		e.alarmSequence = previousSequence
		if found {
			e.alarms[key] = previous
		} else {
			delete(e.alarms, key)
		}
		return nil, false, err
	}
	return frame, true, nil
}

func (e *Engine) nextAlarmSequenceLocked() uint8 {
	if e.alarmSequence == 0 || e.alarmSequence == 255 {
		e.alarmSequence = 1
	} else {
		e.alarmSequence++
	}
	return e.alarmSequence
}

// NotifyAttributeChange commits ONU-originated state and returns one or more
// AVC frames containing the changed attributes that are marked AVC-capable in
// the managed-entity definition. Baseline messages are split at attribute
// boundaries when needed.
func (e *Engine) NotifyAttributeChange(key mib.Key, attributes me.AttributeValueMap,
	device omci.DeviceIdent) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.notifyAttributeChangeLocked(key, attributes, device)
}

func (e *Engine) notifyAttributeChangeLocked(key mib.Key, attributes me.AttributeValueMap,
	device omci.DeviceIdent) ([][]byte, error) {
	if err := e.validateCapabilityAVCLocked(key, attributes); err != nil {
		return nil, err
	}
	changed, err := e.mib.UpdateAutonomous(key, attributes)
	if err != nil {
		return nil, err
	}
	return e.attributeValueChangeFramesLocked(key, changed, device)
}

// validateCapabilityAlarmLocked keeps autonomous alarms within the explicit
// class-288 alarm table used by a device-constrained production store. An
// unrestricted store retains the generated library alarm map behavior.
func (e *Engine) validateCapabilityAlarmLocked(classID me.ClassID, bitmap [28]byte) error {
	_, explicit := e.mib.SupportedAttributeMask(classID)
	if !explicit {
		return nil
	}
	allowed := capabilityAlarmCodes(classID)
	for alarm := uint8(0); alarm < omci.AlarmBitmapSize; alarm++ {
		octet := alarm / 8
		bit := uint(7 - alarm%8)
		if bitmap[octet]&(1<<bit) == 0 {
			continue
		}
		if !containsCapabilityCode(allowed, alarm) {
			return fmt.Errorf("alarm bit %d is not advertised by the ONU capability", alarm)
		}
	}
	return nil
}

// validateCapabilityAVCLocked rejects an ONU-originated state update that
// would produce an AVC absent from the explicit class-288 AVC table. It runs
// before the MIB update so rejected notifications leave state untouched.
func (e *Engine) validateCapabilityAVCLocked(key mib.Key, attributes me.AttributeValueMap) error {
	_, explicit := e.mib.SupportedAttributeMask(key.ClassID)
	if !explicit {
		return nil
	}
	entity, omciErr := me.LoadManagedEntityDefinition(key.ClassID, me.ParamData{EntityID: key.EntityID})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	allowed := capabilityAVCIndexes(key.ClassID)
	for name := range attributes {
		definition, err := me.GetAttributeDefinitionByName(entity.GetAttributeDefinitions(), name)
		if err != nil {
			return fmt.Errorf("AVC attribute %q is not defined for class %d", name, key.ClassID)
		}
		if definition.GetIndex() > 255 ||
			!containsCapabilityCode(allowed, uint8(definition.GetIndex())) {
			return fmt.Errorf("AVC attribute %s is not advertised by the ONU capability", name)
		}
	}
	return nil
}

func containsCapabilityCode(codes []byte, candidate uint8) bool {
	for _, code := range codes {
		if code == candidate {
			return true
		}
	}
	return false
}

func (e *Engine) attributeValueChangeFramesLocked(key mib.Key, changed me.AttributeValueMap,
	device omci.DeviceIdent) ([][]byte, error) {
	if err := validateDeviceIdentifier(device); err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return nil, nil
	}
	device = e.notificationDeviceLocked(device)
	suppressed, err := e.notificationsSuppressedLocked(key)
	if err != nil {
		return nil, err
	}
	if suppressed {
		return nil, nil
	}

	entity, omciErr := me.LoadManagedEntityDefinition(key.ClassID, me.ParamData{EntityID: key.EntityID})
	if omciErr.StatusCode() != me.Success {
		return nil, omciErr.GetError()
	}
	definitions := entity.GetAttributeDefinitions()
	limit := omci.MaxExtendedLength - 12 - 4
	if device == omci.BaselineIdent {
		limit = baselineAVCPayloadLimit
	}

	type avcAttribute struct {
		name  string
		mask  uint16
		size  int
		value interface{}
	}
	ordered := make([]avcAttribute, 0, len(changed))
	for _, index := range me.GetAttributeDefinitionMapKeys(definitions) {
		if index == 0 {
			continue
		}
		definition := definitions[index]
		value, present := changed[definition.GetName()]
		if !present || !definition.Avc {
			continue
		}
		if definition.IsTableAttribute() || definition.GetSize() <= 0 || definition.GetSize() > limit {
			return nil, fmt.Errorf("AVC attribute %s cannot fit in %v format", definition.GetName(), device)
		}
		ordered = append(ordered, avcAttribute{
			name: definition.GetName(), mask: definition.Mask,
			size: definition.GetSize(), value: value,
		})
	}
	if len(ordered) == 0 {
		return nil, nil
	}

	var frames [][]byte
	current := make(me.AttributeValueMap)
	var mask uint16
	used := 0
	flush := func() error {
		frame, serializeErr := serializeAutonomous(device, 0, omci.AttributeValueChangeType,
			&omci.AttributeValueChangeMsg{
				MeBasePacket: omci.MeBasePacket{
					EntityClass:    key.ClassID,
					EntityInstance: key.EntityID,
					Extended:       device == omci.ExtendedIdent,
				},
				AttributeMask: mask,
				Attributes:    current,
			})
		if serializeErr != nil {
			return serializeErr
		}
		frames = append(frames, frame)
		current = make(me.AttributeValueMap)
		mask = 0
		used = 0
		return nil
	}
	for _, attribute := range ordered {
		if used != 0 && used+attribute.size > limit {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		current[attribute.name] = attribute.value
		mask |= attribute.mask
		used += attribute.size
	}
	if len(current) != 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return frames, nil
}

// TestResult serializes an autonomous or OLT-requested test result. A zero TCI
// denotes a self-initiated test; an OLT-requested result retains the request TCI.
func (e *Engine) TestResult(transactionID uint16, key mib.Key, payload []byte,
	device omci.DeviceIdent) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := validateDeviceIdentifier(device); err != nil {
		return nil, err
	}
	device = e.notificationDeviceLocked(device)
	if !e.mib.Exists(key) {
		return nil, fmt.Errorf("test target %v/%#x does not exist", key.ClassID, key.EntityID)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(key.ClassID, me.ParamData{EntityID: key.EntityID})
	if omciErr.StatusCode() != me.Success {
		return nil, omciErr.GetError()
	}
	if !me.SupportsMsgType(entity, me.Test) {
		return nil, fmt.Errorf("managed entity %v/%#x does not support Test", key.ClassID, key.EntityID)
	}
	if transactionID == 0 {
		suppressed, err := e.notificationsSuppressedLocked(key)
		if err != nil {
			return nil, err
		}
		if suppressed {
			return nil, nil
		}
	}
	return serializeAutonomous(device, transactionID, omci.TestResultType,
		&omci.TestResultNotification{
			MeBasePacket: omci.MeBasePacket{
				EntityClass:    key.ClassID,
				EntityInstance: key.EntityID,
				Extended:       device == omci.ExtendedIdent,
			},
			Payload: append([]byte(nil), payload...),
		})
}

func (e *Engine) notificationsSuppressedLocked(key mib.Key) (bool, error) {
	locked, err := e.administrativelyLockedLocked(
		mib.Key{ClassID: me.OnuGClassID, EntityID: 0}, me.OnuG_AdministrativeState)
	if err != nil || locked {
		return locked, err
	}

	if key.ClassID == me.CircuitPackClassID {
		return e.administrativelyLockedLocked(key, me.CircuitPack_AdministrativeState)
	}

	parent := key
	if isEthernetPerformanceClass(key.ClassID) {
		entityID, resolveErr := e.resolveEthernetPerformanceUNILocked(key)
		if resolveErr != nil {
			return false, resolveErr
		}
		parent = mib.Key{ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: entityID}
	} else if key.ClassID == me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID ||
		key.ClassID == me.FecPerformanceMonitoringHistoryDataClassID {
		owner, supported, resolveErr := e.arcOwnerLocked(key)
		if resolveErr != nil {
			return false, resolveErr
		}
		if supported {
			parent = owner
		}
	}

	var slot uint8
	switch parent.ClassID {
	case me.PhysicalPathTerminationPointEthernetUniClassID, me.UniGClassID:
		entityID := parent.EntityID
		if locked, err = e.administrativelyLockedLocked(mib.Key{
			ClassID: me.PhysicalPathTerminationPointEthernetUniClassID, EntityID: entityID,
		}, me.PhysicalPathTerminationPointEthernetUni_AdministrativeState); err != nil || locked {
			return locked, err
		}
		if locked, err = e.administrativelyLockedLocked(mib.Key{
			ClassID: me.UniGClassID, EntityID: entityID,
		}, me.UniG_AdministrativeState); err != nil || locked {
			return locked, err
		}
		slot = uint8(entityID >> 8)
	case me.AniGClassID:
		slot = uint8(parent.EntityID >> 8)
	default:
		return false, nil
	}

	for _, instance := range e.mib.Snapshot() {
		if instance.ClassID != me.CircuitPackClassID || uint8(instance.EntityID) != slot {
			continue
		}
		return e.administrativelyLockedLocked(instance.Key, me.CircuitPack_AdministrativeState)
	}
	return false, nil
}

func (e *Engine) administrativelyLockedLocked(key mib.Key, attribute string) (bool, error) {
	if !e.mib.Exists(key) {
		return false, nil
	}
	definitions, omciErr := me.GetAttributesDefinitions(key.ClassID)
	if omciErr.StatusCode() != me.Success {
		return false, omciErr.GetError()
	}
	definition, err := me.GetAttributeDefinitionByName(definitions, attribute)
	if err != nil {
		return false, err
	}
	instance, err := e.mib.Get(key, definition.Mask)
	if err != nil {
		return false, err
	}
	value, present := instance.Attributes[attribute]
	if !present {
		return false, nil
	}
	state, valid := value.(uint8)
	if !valid || state > 1 {
		return false, fmt.Errorf("managed entity %v/%#x has invalid administrative state %v",
			key.ClassID, key.EntityID, value)
	}
	return state == 1, nil
}

func serializeAutonomous(device omci.DeviceIdent, transactionID uint16,
	messageType omci.MessageType, payload gopacket.SerializableLayer) ([]byte, error) {
	header := &omci.OMCI{
		TransactionID:    transactionID,
		MessageType:      messageType,
		DeviceIdentifier: device,
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false},
		header, payload); err != nil {
		return nil, fmt.Errorf("serialize %s: %w", messageType, err)
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

func validateDeviceIdentifier(device omci.DeviceIdent) error {
	if device != omci.BaselineIdent && device != omci.ExtendedIdent {
		return fmt.Errorf("unsupported OMCI device identifier %#x", byte(device))
	}
	return nil
}

func (e *Engine) notificationDeviceLocked(requested omci.DeviceIdent) omci.DeviceIdent {
	if requested == omci.ExtendedIdent && !e.extendedSeen {
		return omci.BaselineIdent
	}
	return requested
}

func validateAlarmBitmap(alarmMap me.AlarmMap, bitmap [28]byte) error {
	if len(alarmMap) == 0 {
		return fmt.Errorf("managed entity has no alarm map")
	}
	for alarm := 0; alarm < omci.AlarmBitmapSize; alarm++ {
		octet := alarm / 8
		bit := uint(7 - alarm%8)
		if bitmap[octet]&(1<<bit) == 0 {
			continue
		}
		if _, supported := alarmMap[uint8(alarm)]; !supported {
			return fmt.Errorf("alarm bit %d is not defined", alarm)
		}
	}
	return nil
}

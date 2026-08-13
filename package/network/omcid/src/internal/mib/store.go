// SPDX-License-Identifier: Apache-2.0

package mib

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/onu3"
)

type Origin uint8

const (
	OriginONU Origin = iota
	OriginOLT
)

type Key struct {
	ClassID  me.ClassID `json:"class_id"`
	EntityID uint16     `json:"entity_id"`
}

type Instance struct {
	Key
	Attributes me.AttributeValueMap `json:"attributes"`
	Origin     Origin               `json:"origin"`
}

type AttributeCapabilityKey struct {
	ClassID me.ClassID
	Name    string
}

// AttributeCapability overrides the generic wire-width description published
// by the Attribute ME for a device-constrained attribute.
type AttributeCapability struct {
	LowerLimit uint32
	UpperLimit uint32
	BitField   uint32
	CodePoints []uint16
}

type Operation string

const (
	OperationCreate   Operation = "create"
	OperationSet      Operation = "set"
	OperationSetTable Operation = "set-table"
	OperationDelete   Operation = "delete"
	OperationReset    Operation = "reset"
	OperationCommand  Operation = "command"
	// OperationAutonomous applies an ONU-originated service-graph change while
	// preserving MIB data sync. It is currently used when a timed class-310 row
	// expires and must be removed from both the MIB and platform desired state.
	OperationAutonomous Operation = "autonomous"
)

const defaultExtendedVLANTableSize = 64

type Options struct {
	Applier               Applier
	ExtendedVLANTableSize uint16
	// StateDomain is copied into every committed platform document and must
	// match before a persistent MIB can be restored.
	StateDomain string
	// SupportedClasses constrains the device-specific ME surface. A nil or
	// empty list preserves the unrestricted behavior used by small unit-test
	// stores; production callers must provide an explicit platform list.
	SupportedClasses []me.ClassID
	// SupportedAttributeMasks is a complete per-class policy for an explicit
	// SupportedClasses list. A non-nil map must contain exactly one mask for
	// every supported class. This prevents generated optional attributes from
	// being advertised merely because the protocol library knows their shape.
	SupportedAttributeMasks map[me.ClassID]uint16
	// ValidateInstance applies device-specific value constraints after generic
	// G.988 type and semantic validation and before a candidate becomes visible.
	ValidateInstance func(Instance) error
	// AttributeCapabilities describes the same device constraints to an OLT
	// through class 289. Every entry must name an advertised attribute.
	AttributeCapabilities map[AttributeCapabilityKey]AttributeCapability
}

// Change is the immutable candidate state passed to the platform backend.
// The store commits it only after Apply returns successfully.
type Change struct {
	Operation   Operation  `json:"operation"`
	StateDomain string     `json:"state_domain,omitempty"`
	Before      *Instance  `json:"before,omitempty"`
	After       *Instance  `json:"after,omitempty"`
	Snapshot    []Instance `json:"snapshot"`
	MIBDataSync uint8      `json:"mib_data_sync"`
}

type Applier interface {
	Apply(Change) error
}

type ApplyFunc func(Change) error

func (f ApplyFunc) Apply(change Change) error {
	return f(change)
}

// CommandTransaction gates a command-driven MIB update on a second platform
// resource. Commit runs only after the candidate MIB has been persisted;
// Abort must restore any state created while preparing the transaction.
type CommandTransaction interface {
	Commit() error
	Abort() error
}

type ResultError struct {
	Result          me.Results
	FailedMask      uint16
	UnsupportedMask uint16
	Cause           error
}

func (e *ResultError) Error() string {
	if e.Cause == nil {
		return e.Result.String()
	}
	return fmt.Sprintf("%s: %v", e.Result, e.Cause)
}

func (e *ResultError) Unwrap() error {
	return e.Cause
}

type Store struct {
	mu                    sync.RWMutex
	factory               map[Key]Instance
	current               map[Key]Instance
	dataSync              uint8
	applier               Applier
	extendedVLANTableSize uint16
	stateDomain           string
	supportedClasses      map[me.ClassID]struct{}
	supportedAttributes   map[me.ClassID]uint16
	attributeCapabilities map[AttributeCapabilityKey]AttributeCapability
	validateInstance      func(Instance) error
}

func New(factory []Instance) (*Store, error) {
	return NewWithOptions(factory, Options{})
}

func NewWithApplier(factory []Instance, applier Applier) (*Store, error) {
	return NewWithOptions(factory, Options{Applier: applier})
}

func NewWithOptions(factory []Instance, options Options) (*Store, error) {
	tableSize := options.ExtendedVLANTableSize
	if tableSize == 0 {
		tableSize = defaultExtendedVLANTableSize
	}
	if tableSize < 3 {
		return nil, fmt.Errorf("extended VLAN table size %d cannot hold the three mandatory default rules", tableSize)
	}
	s := &Store{
		factory:               make(map[Key]Instance, len(factory)),
		current:               make(map[Key]Instance, len(factory)),
		applier:               options.Applier,
		extendedVLANTableSize: tableSize,
		stateDomain:           options.StateDomain,
		validateInstance:      options.ValidateInstance,
	}
	if options.SupportedAttributeMasks != nil && len(options.SupportedClasses) == 0 {
		return nil, fmt.Errorf("supported attribute masks require an explicit supported class list")
	}
	if len(options.SupportedClasses) != 0 {
		s.supportedClasses = make(map[me.ClassID]struct{}, len(options.SupportedClasses))
		s.supportedAttributes = make(map[me.ClassID]uint16, len(options.SupportedClasses))
		for _, classID := range options.SupportedClasses {
			if _, duplicate := s.supportedClasses[classID]; duplicate {
				return nil, fmt.Errorf("duplicate supported managed-entity class %v", classID)
			}
			entity, result := loadDefinition(classID, 0, nil)
			if result != nil {
				return nil, fmt.Errorf("invalid supported managed-entity class %v: %w", classID, result)
			}
			s.supportedClasses[classID] = struct{}{}
			definition := entity.GetManagedEntityDefinition()
			if options.SupportedAttributeMasks != nil {
				mask, present := options.SupportedAttributeMasks[classID]
				if !present {
					return nil, fmt.Errorf("supported managed-entity class %v has no attribute policy", classID)
				}
				if unsupported := mask &^ definition.AllowedAttributeMask; unsupported != 0 {
					return nil, fmt.Errorf("supported managed-entity class %v attribute mask %#x includes unknown bits %#x",
						classID, mask, unsupported)
				}
				s.supportedAttributes[classID] = mask
			} else if definition.Access != me.CreatedByOnu || isCapabilityClass(classID) {
				s.supportedAttributes[classID] = definition.AllowedAttributeMask
			}
		}
		if options.SupportedAttributeMasks != nil {
			for classID := range options.SupportedAttributeMasks {
				if _, present := s.supportedClasses[classID]; !present {
					return nil, fmt.Errorf("attribute policy contains unsupported managed-entity class %v", classID)
				}
			}
		}
	}
	if len(options.AttributeCapabilities) != 0 {
		if options.SupportedAttributeMasks == nil {
			return nil, fmt.Errorf("attribute capabilities require an explicit supported attribute policy")
		}
		s.attributeCapabilities = make(map[AttributeCapabilityKey]AttributeCapability,
			len(options.AttributeCapabilities))
		for key, capability := range options.AttributeCapabilities {
			if _, supported := s.supportedClasses[key.ClassID]; !supported {
				return nil, fmt.Errorf("attribute capability contains unsupported managed-entity class %v", key.ClassID)
			}
			definitions, omciErr := me.GetAttributesDefinitions(key.ClassID)
			if omciErr.StatusCode() != me.Success {
				return nil, fmt.Errorf("load managed-entity class %v attributes: %w",
					key.ClassID, omciErr.GetError())
			}
			definition, err := me.GetAttributeDefinitionByName(definitions, key.Name)
			if err != nil {
				return nil, fmt.Errorf("invalid attribute capability %v/%s: %w", key.ClassID, key.Name, err)
			}
			if definition.Mask&s.supportedAttributes[key.ClassID] == 0 {
				return nil, fmt.Errorf("attribute capability %v/%s is not advertised", key.ClassID, key.Name)
			}
			if capability.LowerLimit > capability.UpperLimit {
				return nil, fmt.Errorf("attribute capability %v/%s has lower limit %d above upper limit %d",
					key.ClassID, key.Name, capability.LowerLimit, capability.UpperLimit)
			}
			if definition.AttributeType != me.EnumerationAttributeType && len(capability.CodePoints) != 0 {
				return nil, fmt.Errorf("non-enumerated attribute capability %v/%s has code points",
					key.ClassID, key.Name)
			}
			if definition.AttributeType == me.EnumerationAttributeType {
				if len(capability.CodePoints) == 0 {
					return nil, fmt.Errorf("enumerated attribute capability %v/%s has no code points",
						key.ClassID, key.Name)
				}
				maximum := uint32(maximumCapabilityValue(definition.GetSize()))
				for index, value := range capability.CodePoints {
					if uint32(value) > maximum {
						return nil, fmt.Errorf("attribute capability %v/%s code point %d exceeds its wire size",
							key.ClassID, key.Name, value)
					}
					if index != 0 && value <= capability.CodePoints[index-1] {
						return nil, fmt.Errorf("attribute capability %v/%s code points are not strictly increasing",
							key.ClassID, key.Name)
					}
				}
			} else if definition.AttributeType == me.UnsignedIntegerAttributeType ||
				definition.AttributeType == me.CounterAttributeType ||
				definition.AttributeType == me.PointerAttributeType {
				if uint64(capability.UpperLimit) > maximumCapabilityValue(definition.GetSize()) {
					return nil, fmt.Errorf("attribute capability %v/%s upper limit %d exceeds its wire size",
						key.ClassID, key.Name, capability.UpperLimit)
				}
			} else if definition.AttributeType != me.BitFieldAttributeType {
				return nil, fmt.Errorf("attribute capability %v/%s has unsupported format %v",
					key.ClassID, key.Name, definition.AttributeType)
			}
			copy := capability
			copy.CodePoints = append([]uint16(nil), capability.CodePoints...)
			s.attributeCapabilities[key] = copy
		}
	}

	for _, instance := range factory {
		if !s.supportsClass(instance.ClassID) {
			return nil, fmt.Errorf("factory ME %v/%#x is not in the supported class list",
				instance.ClassID, instance.EntityID)
		}
		instance.Origin = OriginONU
		normalized, err := s.normalize(instance)
		if err != nil {
			return nil, fmt.Errorf("invalid factory ME %v/%#x: %w", instance.ClassID, instance.EntityID, err)
		}
		if _, exists := s.factory[normalized.Key]; exists {
			return nil, fmt.Errorf("duplicate factory ME %v/%#x", instance.ClassID, instance.EntityID)
		}
		s.factory[normalized.Key] = normalized
		s.current[normalized.Key] = cloneInstance(normalized)
		if s.supportedAttributes != nil {
			entity, result := loadDefinition(normalized.ClassID, normalized.EntityID, normalized.Attributes)
			if result != nil {
				return nil, result
			}
			if options.SupportedAttributeMasks != nil {
				if err := s.validateSupportedAttributes(entity, normalized.Attributes); err != nil {
					return nil, fmt.Errorf("factory ME %v/%#x has unsupported attributes: %w",
						normalized.ClassID, normalized.EntityID, err)
				}
				continue
			}
			for name := range normalized.Attributes {
				if name == me.ManagedEntityID {
					continue
				}
				attribute, err := me.GetAttributeDefinitionByName(entity.GetAttributeDefinitions(), name)
				if err != nil {
					return nil, fmt.Errorf("factory ME %v/%#x has unknown attribute %s",
						normalized.ClassID, normalized.EntityID, name)
				}
				s.supportedAttributes[normalized.ClassID] |= attribute.Mask
			}
		}
	}
	s.setDataSyncLocked(0)
	return s, nil
}

func (s *Store) DataSync() uint8 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dataSync
}

func (s *Store) Exists(key Key) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.current[key]
	return exists
}

// SupportsClass reports whether the platform advertises and accepts a managed
// entity class. Stores without an explicit policy remain unrestricted.
func (s *Store) SupportsClass(classID me.ClassID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.supportsClass(classID)
}

// SupportedClasses returns the explicit device capability list. A nil result
// means that the store has no device-specific policy and must not be used to
// synthesize capability MEs.
func (s *Store) SupportedClasses() []me.ClassID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.supportedClasses == nil {
		return nil
	}
	classes := make([]me.ClassID, 0, len(s.supportedClasses))
	for classID := range s.supportedClasses {
		classes = append(classes, classID)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	return classes
}

// SupportedAttributeMask returns the attribute surface for an explicitly
// supported class. The boolean is false for unrestricted stores or classes
// outside the device policy.
func (s *Store) SupportedAttributeMask(classID me.ClassID) (uint16, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.supportedAttributeMask(classID)
}

func (s *Store) supportsClass(classID me.ClassID) bool {
	if s.supportedClasses == nil {
		return true
	}
	_, supported := s.supportedClasses[classID]
	return supported
}

func (s *Store) Get(key Key, mask uint16) (Instance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	instance, exists := s.current[key]
	if !exists {
		return Instance{}, s.unknownKeyError(key)
	}

	entity, result := loadDefinition(key.ClassID, key.EntityID, instance.Attributes)
	if result != nil {
		return Instance{}, result
	}
	allowed := entity.GetAllowedAttributeMask()
	if supported, explicit := s.supportedAttributeMask(key.ClassID); explicit {
		allowed &= supported
	}
	unsupported := mask &^ allowed
	selectedMask := mask & allowed

	selected := make(me.AttributeValueMap)
	for index, definition := range entity.GetAttributeDefinitions() {
		if index == 0 || selectedMask&definition.Mask != 0 {
			if value, ok := instance.Attributes[definition.GetName()]; ok {
				selected[definition.GetName()] = cloneValue(value)
			}
		}
	}
	instance.Attributes = selected
	if unsupported != 0 {
		return instance, &ResultError{Result: me.AttributeFailure, UnsupportedMask: unsupported}
	}
	return instance, nil
}

func (s *Store) Create(classID me.ClassID, entityID uint16, attributes me.AttributeValueMap) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := Key{ClassID: classID, EntityID: entityID}
	if !s.supportsClass(classID) {
		return &ResultError{Result: me.UnknownEntity,
			Cause: fmt.Errorf("managed entity class %#x is not supported by this ONU", classID)}
	}
	if _, exists := s.current[key]; exists {
		return &ResultError{Result: me.InstanceExists}
	}

	entity, result := loadDefinition(classID, entityID, attributes)
	if result != nil {
		return result
	}
	definition := entity.GetManagedEntityDefinition()
	if !me.SupportsMsgType(entity, me.Create) ||
		(definition.Access != me.CreatedByOlt && definition.Access != me.CreatedByBoth) {
		return &ResultError{Result: me.NotSupported}
	}
	if err := s.validateSupportedAttributes(entity, attributes); err != nil {
		return err
	}
	if err := validateAccess(entity, attributes, me.SetByCreate); err != nil {
		return err
	}
	createdAttributes := cloneAttributes(attributes)
	if omciErr := me.MergeInDefaultValues(classID, createdAttributes); omciErr.StatusCode() != me.Success {
		return &ResultError{Result: omciErr.StatusCode(), Cause: omciErr.GetError()}
	}
	s.pruneUnsupportedAttributes(classID, createdAttributes)
	instance := Instance{
		Key:        key,
		Attributes: createdAttributes,
		Origin:     OriginOLT,
	}
	initializeCreatedInstance(&instance, s.extendedVLANTableSize)
	s.pruneUnsupportedAttributes(classID, instance.Attributes)
	instance, err := s.normalize(instance)
	if err != nil {
		return err
	}
	next := cloneInstances(s.current)
	next[key] = instance
	return s.commitLocked(OperationCreate, nil, &instance, next, s.nextDataSyncLocked())
}

func (s *Store) Set(key Key, attributes me.AttributeValueMap) error {
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
	if !me.SupportsMsgType(entity, me.Set) {
		return &ResultError{Result: me.NotSupported}
	}
	if err := s.validateSupportedAttributes(entity, attributes); err != nil {
		return err
	}
	if err := validateAccess(entity, attributes, me.Write); err != nil {
		return err
	}

	next := cloneInstance(current)
	for name, value := range attributes {
		if name == me.ManagedEntityID {
			continue
		}
		next.Attributes[name] = cloneValue(value)
	}
	normalized, err := s.normalize(next)
	if err != nil {
		return err
	}
	dataSync := s.nextDataSyncLocked()
	if key.ClassID == me.OnuDataClassID && key.EntityID == 0 {
		if requested, present := attributes[me.OnuData_MibDataSync]; present {
			value, ok := requested.(uint8)
			if !ok {
				return &ResultError{Result: me.ParameterError,
					Cause: fmt.Errorf("MIB data sync has invalid type %T", requested)}
			}
			dataSync = incrementDataSync(value)
			normalized.Attributes[me.OnuData_MibDataSync] = dataSync
		}
	}
	if reflect.DeepEqual(current.Attributes, normalized.Attributes) {
		return nil
	}
	proposed := cloneInstances(s.current)
	proposed[key] = normalized
	return s.commitLocked(OperationSet, &current, &normalized, proposed, dataSync)
}

// UpdateAutonomous records attributes changed by the ONU itself. Autonomous
// changes do not advance MIB data sync and are not sent to the platform
// applier: they describe hardware state that has already changed. The returned
// map contains only values that differ from the committed MIB.
func (s *Store) UpdateAutonomous(key Key, attributes me.AttributeValueMap) (me.AttributeValueMap, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.current[key]
	if !exists {
		return nil, s.unknownKeyError(key)
	}
	entity, result := loadDefinition(key.ClassID, key.EntityID, current.Attributes)
	if result != nil {
		return nil, result
	}
	if err := s.validateSupportedAttributes(entity, attributes); err != nil {
		return nil, err
	}

	definitions := entity.GetAttributeDefinitions()
	var failed uint16
	var unsupported uint16
	for name := range attributes {
		if name == me.ManagedEntityID ||
			(key.ClassID == me.OnuDataClassID && name == me.OnuData_MibDataSync) {
			unsupported = 0xffff
			continue
		}
		definition, err := me.GetAttributeDefinitionByName(definitions, name)
		if err != nil {
			unsupported = 0xffff
			continue
		}
		if !me.SupportsAttributeAccess(*definition, me.Read) {
			failed |= definition.Mask
		}
	}
	if failed != 0 || unsupported != 0 {
		return nil, &ResultError{
			Result:          me.AttributeFailure,
			FailedMask:      failed,
			UnsupportedMask: unsupported,
		}
	}

	next := cloneInstance(current)
	for name, value := range attributes {
		next.Attributes[name] = cloneValue(value)
	}
	normalized, err := s.normalize(next)
	if err != nil {
		return nil, err
	}

	changed := make(me.AttributeValueMap)
	for name := range attributes {
		value := normalized.Attributes[name]
		if !reflect.DeepEqual(current.Attributes[name], value) {
			changed[name] = cloneValue(value)
		}
	}
	if len(changed) == 0 {
		return changed, nil
	}
	s.current[key] = normalized
	return changed, nil
}

// UpdateAutonomousBatch atomically records multiple ONU-originated updates.
// It does not advance MIB data sync or call the service applier. Either every
// instance is validated and replaced, or the current MIB remains unchanged.
func (s *Store) UpdateAutonomousBatch(updates map[Key]me.AttributeValueMap) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	proposed := cloneInstances(s.current)
	for key, attributes := range updates {
		current, exists := proposed[key]
		if !exists {
			return s.unknownKeyError(key)
		}
		entity, result := loadDefinition(key.ClassID, key.EntityID, current.Attributes)
		if result != nil {
			return result
		}
		if err := s.validateSupportedAttributes(entity, attributes); err != nil {
			return err
		}

		definitions := entity.GetAttributeDefinitions()
		var failed uint16
		var unsupported uint16
		for name := range attributes {
			if name == me.ManagedEntityID ||
				(key.ClassID == me.OnuDataClassID && name == me.OnuData_MibDataSync) {
				unsupported = 0xffff
				continue
			}
			definition, err := me.GetAttributeDefinitionByName(definitions, name)
			if err != nil {
				unsupported = 0xffff
				continue
			}
			if !me.SupportsAttributeAccess(*definition, me.Read) {
				failed |= definition.Mask
			}
		}
		if failed != 0 || unsupported != 0 {
			return &ResultError{
				Result: me.AttributeFailure, FailedMask: failed,
				UnsupportedMask: unsupported,
			}
		}

		next := cloneInstance(current)
		for name, value := range attributes {
			next.Attributes[name] = cloneValue(value)
		}
		normalized, err := s.normalize(next)
		if err != nil {
			return err
		}
		proposed[key] = normalized
	}
	s.current = proposed
	return nil
}

// UpdateByCommand atomically records read-only state changed as the result of
// one OLT action. Multiple MEs can change, but MIB data sync advances only once
// for the command. OperationCommand lets a transactional applier persist the
// MIB without reapplying an unchanged service graph.
func (s *Store) UpdateByCommand(updates map[Key]me.AttributeValueMap) error {
	return s.updateByCommand(updates, nil)
}

// UpdateByCommandTransactional couples a command-driven MIB mutation to a
// prepared platform transaction. If either side fails, the store retains its
// original state and best-effort restores both the external transaction and
// the previously persisted MIB snapshot.
func (s *Store) UpdateByCommandTransactional(updates map[Key]me.AttributeValueMap,
	transaction CommandTransaction) error {
	if transaction == nil {
		return &ResultError{Result: me.ProcessingError,
			Cause: fmt.Errorf("command transaction is nil")}
	}
	return s.updateByCommand(updates, transaction)
}

func (s *Store) updateByCommand(updates map[Key]me.AttributeValueMap,
	transaction CommandTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	proposed := cloneInstances(s.current)
	changed := false
	for key, attributes := range updates {
		current, exists := s.current[key]
		if !exists {
			return abortCommandTransaction(transaction, s.unknownKeyError(key))
		}
		entity, result := loadDefinition(key.ClassID, key.EntityID, current.Attributes)
		if result != nil {
			return abortCommandTransaction(transaction, result)
		}
		if err := s.validateSupportedAttributes(entity, attributes); err != nil {
			return abortCommandTransaction(transaction, err)
		}
		definitions := entity.GetAttributeDefinitions()
		var failed uint16
		var unsupported uint16
		for name := range attributes {
			if name == me.ManagedEntityID ||
				(key.ClassID == me.OnuDataClassID && name == me.OnuData_MibDataSync) {
				unsupported = 0xffff
				continue
			}
			definition, err := me.GetAttributeDefinitionByName(definitions, name)
			if err != nil {
				unsupported = 0xffff
				continue
			}
			if !me.SupportsAttributeAccess(*definition, me.Read) {
				failed |= definition.Mask
			}
		}
		if failed != 0 || unsupported != 0 {
			return abortCommandTransaction(transaction, &ResultError{
				Result:          me.AttributeFailure,
				FailedMask:      failed,
				UnsupportedMask: unsupported,
			})
		}

		next := cloneInstance(current)
		for name, value := range attributes {
			next.Attributes[name] = cloneValue(value)
		}
		normalized, err := s.normalize(next)
		if err != nil {
			return abortCommandTransaction(transaction, err)
		}
		if !reflect.DeepEqual(current.Attributes, normalized.Attributes) {
			proposed[key] = normalized
			changed = true
		}
	}
	if !changed {
		if transaction != nil {
			if err := transaction.Commit(); err != nil {
				return commandTransactionFailure(transaction, nil,
					fmt.Errorf("commit platform transaction: %w", err))
			}
		}
		return nil
	}

	dataSync := s.nextDataSyncLocked()
	setDataSync(proposed, dataSync)
	if transaction == nil {
		return s.commitLocked(OperationCommand, nil, nil, proposed, dataSync)
	}
	change := Change{
		Operation: OperationCommand, StateDomain: s.stateDomain,
		Snapshot: snapshotInstances(proposed), MIBDataSync: dataSync,
	}
	if s.applier != nil {
		if err := s.applier.Apply(change); err != nil {
			return commandTransactionFailure(transaction, nil,
				fmt.Errorf("apply platform state: %w", err))
		}
	}
	if err := transaction.Commit(); err != nil {
		abortErr := transaction.Abort()
		var rollbackErr error
		if s.applier != nil {
			rollback := Change{
				Operation: OperationCommand, StateDomain: s.stateDomain,
				Snapshot:    snapshotInstances(s.current),
				MIBDataSync: s.dataSync,
			}
			if err := s.applier.Apply(rollback); err != nil {
				rollbackErr = fmt.Errorf("restore persisted MIB state: %w", err)
			}
		}
		return commandTransactionError(fmt.Errorf("commit platform transaction: %w", err),
			abortErr, rollbackErr)
	}
	s.current = proposed
	s.dataSync = dataSync
	return nil
}

func abortCommandTransaction(transaction CommandTransaction, cause error) error {
	if transaction == nil {
		return cause
	}
	if err := transaction.Abort(); err != nil {
		return errors.Join(cause, fmt.Errorf("abort platform transaction: %w", err))
	}
	return cause
}

func commandTransactionFailure(transaction CommandTransaction, rollbackErr, cause error) error {
	return commandTransactionError(cause, transaction.Abort(), rollbackErr)
}

func commandTransactionError(cause, abortErr, rollbackErr error) error {
	errorsToJoin := []error{cause}
	if abortErr != nil {
		errorsToJoin = append(errorsToJoin, fmt.Errorf("abort platform transaction: %w", abortErr))
	}
	if rollbackErr != nil {
		errorsToJoin = append(errorsToJoin, rollbackErr)
	}
	return &ResultError{Result: me.ProcessingError, Cause: errors.Join(errorsToJoin...)}
}

func (s *Store) Delete(key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance, exists := s.current[key]
	if !exists {
		return s.unknownKeyError(key)
	}
	entity, result := loadDefinition(key.ClassID, key.EntityID, instance.Attributes)
	if result != nil {
		return result
	}
	definition := entity.GetManagedEntityDefinition()
	if instance.Origin == OriginONU || !me.SupportsMsgType(entity, me.Delete) ||
		(definition.Access != me.CreatedByOlt && definition.Access != me.CreatedByBoth) {
		return &ResultError{Result: me.NotSupported}
	}

	next := cloneInstances(s.current)
	delete(next, key)
	return s.commitLocked(OperationDelete, &instance, nil, next, s.nextDataSyncLocked())
}

func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := make(map[Key]Instance, len(s.factory))
	for key, instance := range s.factory {
		next[key] = cloneInstance(instance)
	}
	preserveONU3State(s.current, next)
	return s.commitLocked(OperationReset, nil, nil, next, 0)
}

func preserveONU3State(current, reset map[Key]Instance) {
	key := Key{ClassID: me.Onu3GClassID, EntityID: 0}
	before, present := current[key]
	after, supported := reset[key]
	if !present || !supported {
		return
	}
	for _, name := range []string{
		me.Onu3G_LatestRestartReason,
		me.Onu3G_NumberOfValidStatusSnapshots,
		me.Onu3G_NextStatusSnapshotIndex,
		me.Onu3G_StatusSnapshotRecordTable,
		me.Onu3G_MostRecentStatusSnapshot,
	} {
		if value, exists := before.Attributes[name]; exists {
			after.Attributes[name] = cloneValue(value)
		}
	}
	reset[key] = after
}

func (s *Store) Snapshot() []Instance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return snapshotInstances(s.current)
}

func snapshotInstances(instances map[Key]Instance) []Instance {
	items := make([]Instance, 0, len(instances))
	for _, instance := range instances {
		items = append(items, cloneInstance(instance))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ClassID == items[j].ClassID {
			return items[i].EntityID < items[j].EntityID
		}
		return items[i].ClassID < items[j].ClassID
	})
	return items
}

func (s *Store) commitLocked(operation Operation, before, after *Instance,
	next map[Key]Instance, dataSync uint8) error {
	setDataSync(next, dataSync)
	change := Change{
		Operation:   operation,
		StateDomain: s.stateDomain,
		Before:      cloneInstancePointer(before),
		After:       cloneInstancePointer(after),
		Snapshot:    snapshotInstances(next),
		MIBDataSync: dataSync,
	}
	if s.applier != nil {
		if err := s.applier.Apply(change); err != nil {
			return &ResultError{Result: me.ProcessingError, Cause: fmt.Errorf("apply platform state: %w", err)}
		}
	}
	s.current = next
	s.dataSync = dataSync
	return nil
}

func normalize(instance Instance) (Instance, error) {
	entity, result := loadDefinition(instance.ClassID, instance.EntityID, instance.Attributes)
	if result != nil {
		return Instance{}, result
	}
	instance.Attributes = cloneAttributes(entity.GetAttributeValueMap())
	if err := validateSemantics(instance); err != nil {
		return Instance{}, err
	}
	return instance, nil
}

func (s *Store) normalize(instance Instance) (Instance, error) {
	normalized, err := normalize(instance)
	if err != nil {
		return Instance{}, err
	}
	if err := s.validateAttributeCapabilities(normalized); err != nil {
		return Instance{}, err
	}
	if s.validateInstance != nil {
		if err := s.validateInstance(cloneInstance(normalized)); err != nil {
			return Instance{}, err
		}
	}
	return normalized, nil
}

func (s *Store) validateAttributeCapabilities(instance Instance) error {
	for key, capability := range s.attributeCapabilities {
		if key.ClassID != instance.ClassID {
			continue
		}
		value, present := instance.Attributes[key.Name]
		if !present {
			continue
		}
		definitions, omciErr := me.GetAttributesDefinitions(key.ClassID)
		if omciErr.StatusCode() != me.Success {
			return &ResultError{Result: me.ProcessingError, Cause: omciErr.GetError()}
		}
		definition, err := me.GetAttributeDefinitionByName(definitions, key.Name)
		if err != nil {
			return &ResultError{Result: me.ProcessingError, Cause: err}
		}
		unsigned, valid := unsignedCapabilityValue(value)
		if !valid {
			return &ResultError{Result: me.ParameterError,
				Cause: fmt.Errorf("attribute %s has unsupported capability value type %T", key.Name, value)}
		}
		valid = false
		switch definition.AttributeType {
		case me.EnumerationAttributeType:
			for _, codePoint := range capability.CodePoints {
				if unsigned == uint64(codePoint) {
					valid = true
					break
				}
			}
		case me.BitFieldAttributeType:
			valid = unsigned&^uint64(capability.BitField) == 0
		default:
			valid = unsigned >= uint64(capability.LowerLimit) &&
				unsigned <= uint64(capability.UpperLimit)
		}
		if !valid {
			return &ResultError{Result: me.AttributeFailure, FailedMask: definition.Mask,
				Cause: fmt.Errorf("attribute %s value %d is outside the advertised device capability",
					key.Name, unsigned)}
		}
	}
	return nil
}

func maximumCapabilityValue(size int) uint64 {
	if size <= 0 || size >= 8 {
		return ^uint64(0)
	}
	return uint64(1)<<(uint(size)*8) - 1
}

func unsignedCapabilityValue(value interface{}) (uint64, bool) {
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

func validateSemantics(instance Instance) error {
	attributes := instance.Attributes
	if arc, present := byteAttribute(attributes, "Arc"); present && arc > 1 {
		return &ResultError{Result: me.AttributeFailure, FailedMask: attributeMask(instance.ClassID, "Arc"),
			Cause: fmt.Errorf("ARC value %d is not 0 or 1", arc)}
	}
	switch instance.ClassID {
	case me.Onu3GClassID:
		if err := validateONU3State(instance); err != nil {
			return err
		}
	case me.OnuGClassID, me.CircuitPackClassID,
		me.PhysicalPathTerminationPointEthernetUniClassID, me.UniGClassID:
		if state, present := byteAttribute(attributes, "AdministrativeState"); present && state > 1 {
			return &ResultError{Result: me.AttributeFailure,
				FailedMask: attributeMask(instance.ClassID, "AdministrativeState"),
				Cause:      fmt.Errorf("administrative state %d is not 0 or 1", state)}
		}
	}
	if instance.ClassID != me.AniGClassID {
		return nil
	}

	sf, sfPresent := byteAttribute(attributes, me.AniG_SignalFailThreshold)
	sd, sdPresent := byteAttribute(attributes, me.AniG_SignalDegradeThreshold)
	if sfPresent && (sf < 3 || sf > 8) {
		return attributeValueError(instance.ClassID, me.AniG_SignalFailThreshold,
			"SF threshold %d is outside 3..8", sf)
	}
	if sdPresent && (sd < 4 || sd > 10) {
		return attributeValueError(instance.ClassID, me.AniG_SignalDegradeThreshold,
			"SD threshold %d is outside 4..10", sd)
	}
	if sfPresent && sdPresent && sd <= sf {
		return &ResultError{Result: me.AttributeFailure,
			FailedMask: attributeMask(instance.ClassID, me.AniG_SignalFailThreshold) |
				attributeMask(instance.ClassID, me.AniG_SignalDegradeThreshold),
			Cause: fmt.Errorf("SD threshold %d must be greater than SF threshold %d", sd, sf)}
	}

	lowerRX, lowerRXPresent := byteAttribute(attributes, me.AniG_LowerOpticalThreshold)
	upperRX, upperRXPresent := byteAttribute(attributes, me.AniG_UpperOpticalThreshold)
	if lowerRXPresent && upperRXPresent && lowerRX != 0xff && upperRX != 0xff && lowerRX < upperRX {
		return &ResultError{Result: me.AttributeFailure,
			FailedMask: attributeMask(instance.ClassID, me.AniG_LowerOpticalThreshold) |
				attributeMask(instance.ClassID, me.AniG_UpperOpticalThreshold),
			Cause: fmt.Errorf("lower receive threshold %#x is above upper threshold %#x", lowerRX, upperRX)}
	}

	lowerTX, lowerTXPresent := byteAttribute(attributes, me.AniG_LowerTransmitPowerThreshold)
	upperTX, upperTXPresent := byteAttribute(attributes, me.AniG_UpperTransmitPowerThreshold)
	if lowerTXPresent && upperTXPresent && lowerTX != 0x81 && upperTX != 0x81 &&
		int8(lowerTX) > int8(upperTX) {
		return &ResultError{Result: me.AttributeFailure,
			FailedMask: attributeMask(instance.ClassID, me.AniG_LowerTransmitPowerThreshold) |
				attributeMask(instance.ClassID, me.AniG_UpperTransmitPowerThreshold),
			Cause: fmt.Errorf("lower transmit threshold %d is above upper threshold %d",
				int8(lowerTX), int8(upperTX))}
	}
	return nil
}

func validateONU3State(instance Instance) error {
	attributes := instance.Attributes
	total, totalOK := attributes[me.Onu3G_TotalNumberOfStatusSnapshots].(uint16)
	valid, validOK := attributes[me.Onu3G_NumberOfValidStatusSnapshots].(uint16)
	next, nextOK := attributes[me.Onu3G_NextStatusSnapshotIndex].(uint16)
	table, tableOK := attributes[me.Onu3G_StatusSnapshotRecordTable].(me.TableRows)
	recent, recentOK := attributes[me.Onu3G_MostRecentStatusSnapshot].([]byte)
	if !totalOK || !validOK || !nextOK || !tableOK || !recentOK {
		return &ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G status snapshot attributes have invalid types")}
	}
	if total == 0 || valid > total || next >= total {
		return &ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G status snapshot S/M/K = %d/%d/%d is invalid", total, valid, next)}
	}
	if valid < total && next != valid {
		return &ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G partial status table has M/K = %d/%d", valid, next)}
	}
	if table.NumRows != int(valid) || len(table.Rows) != int(valid)*onu3.RecordSize {
		return &ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G status table has %d rows/%d bytes for M=%d",
				table.NumRows, len(table.Rows), valid)}
	}
	if len(recent) != onu3.RecordSize {
		return &ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G most recent snapshot has %d bytes", len(recent))}
	}
	if enhanced, present := attributes[me.Onu3G_EnhancedMode].(uint8); present && enhanced > 1 {
		return &ResultError{Result: me.ParameterError,
			Cause: fmt.Errorf("ONU3-G enhanced mode %d is not boolean", enhanced)}
	}
	if valid != 0 {
		latest := (int(next) + int(total) - 1) % int(total)
		offset := latest * onu3.RecordSize
		if offset+onu3.RecordSize > len(table.Rows) ||
			!reflect.DeepEqual(recent, table.Rows[offset:offset+onu3.RecordSize]) {
			return &ResultError{Result: me.ParameterError,
				Cause: fmt.Errorf("ONU3-G most recent snapshot does not match table index %d", latest)}
		}
	}
	return nil
}

func byteAttribute(attributes me.AttributeValueMap, name string) (uint8, bool) {
	value, present := attributes[name]
	if !present {
		return 0, false
	}
	byteValue, valid := value.(uint8)
	return byteValue, valid
}

func attributeMask(classID me.ClassID, name string) uint16 {
	definitions, omciErr := me.GetAttributesDefinitions(classID)
	if omciErr.StatusCode() != me.Success {
		return 0
	}
	definition, err := me.GetAttributeDefinitionByName(definitions, name)
	if err != nil {
		return 0
	}
	return definition.Mask
}

func attributeValueError(classID me.ClassID, name, format string, arguments ...interface{}) error {
	return &ResultError{Result: me.AttributeFailure, FailedMask: attributeMask(classID, name),
		Cause: fmt.Errorf(format, arguments...)}
}

func loadDefinition(classID me.ClassID, entityID uint16, attributes me.AttributeValueMap) (*me.ManagedEntity, *ResultError) {
	entity, omciErr := me.LoadManagedEntityDefinition(classID, me.ParamData{
		EntityID:   entityID,
		Attributes: cloneAttributes(attributes),
	})
	if omciErr.StatusCode() != me.Success {
		result := omciErr.StatusCode()
		if result == me.ProcessingError {
			result = me.UnknownEntity
		}
		return nil, &ResultError{Result: result, Cause: omciErr.GetError()}
	}
	classSupport := entity.GetManagedEntityDefinition().GetClassSupport()
	if classSupport == me.UnsupportedManagedEntity ||
		classSupport == me.UnsupportedVendorSpecificManagedEntity {
		return nil, &ResultError{Result: me.UnknownEntity,
			Cause: fmt.Errorf("managed entity class %#x is unknown", classID)}
	}
	return entity, nil
}

func validateAccess(entity *me.ManagedEntity, attributes me.AttributeValueMap, required me.AttributeAccess) error {
	definitions := entity.GetAttributeDefinitions()
	var failed uint16
	var unsupported uint16

	for name := range attributes {
		if name == me.ManagedEntityID {
			continue
		}
		found := false
		for index, definition := range definitions {
			if index == 0 || definition.GetName() != name {
				continue
			}
			found = true
			if !me.SupportsAttributeAccess(definition, required) {
				failed |= definition.Mask
			}
			break
		}
		if !found {
			unsupported = 0xffff
		}
	}
	if failed != 0 || unsupported != 0 {
		return &ResultError{
			Result:          me.AttributeFailure,
			FailedMask:      failed,
			UnsupportedMask: unsupported,
		}
	}
	return nil
}

func unknownKeyError(key Key) error {
	if _, result := loadDefinition(key.ClassID, key.EntityID, nil); result != nil {
		return result
	}
	return &ResultError{Result: me.UnknownInstance}
}

func (s *Store) unknownKeyError(key Key) error {
	if !s.supportsClass(key.ClassID) {
		return &ResultError{Result: me.UnknownEntity,
			Cause: fmt.Errorf("managed entity class %#x is not supported by this ONU", key.ClassID)}
	}
	return unknownKeyError(key)
}

func (s *Store) supportedAttributeMask(classID me.ClassID) (uint16, bool) {
	if s.supportedAttributes == nil {
		return 0, false
	}
	mask, supported := s.supportedAttributes[classID]
	return mask, supported
}

func (s *Store) AttributeCapability(classID me.ClassID, name string) (AttributeCapability, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	capability, present := s.attributeCapabilities[AttributeCapabilityKey{ClassID: classID, Name: name}]
	capability.CodePoints = append([]uint16(nil), capability.CodePoints...)
	return capability, present
}

func (s *Store) validateSupportedAttributes(entity *me.ManagedEntity, attributes me.AttributeValueMap) error {
	supported, explicit := s.supportedAttributeMask(entity.GetClassID())
	if !explicit {
		return nil
	}
	definitions := entity.GetAttributeDefinitions()
	var unsupported uint16
	for name := range attributes {
		if name == me.ManagedEntityID {
			continue
		}
		definition, err := me.GetAttributeDefinitionByName(definitions, name)
		if err != nil {
			unsupported = 0xffff
			continue
		}
		if definition.Mask&supported == 0 {
			unsupported |= definition.Mask
		}
	}
	if unsupported != 0 {
		return &ResultError{Result: me.AttributeFailure, UnsupportedMask: unsupported}
	}
	return nil
}

func (s *Store) pruneUnsupportedAttributes(classID me.ClassID, attributes me.AttributeValueMap) {
	supported, explicit := s.supportedAttributeMask(classID)
	if !explicit {
		return
	}
	definitions, omciErr := me.GetAttributesDefinitions(classID)
	if omciErr.StatusCode() != me.Success {
		return
	}
	for name := range attributes {
		if name == me.ManagedEntityID {
			continue
		}
		definition, err := me.GetAttributeDefinitionByName(definitions, name)
		if err != nil || definition.Mask&supported == 0 {
			delete(attributes, name)
		}
	}
}

func isCapabilityClass(classID me.ClassID) bool {
	switch classID {
	case me.OmciClassID, me.ManagedEntityMeClassID, me.AttributeMeClassID:
		return true
	default:
		return false
	}
}

func (s *Store) nextDataSyncLocked() uint8 {
	return incrementDataSync(s.dataSync)
}

func incrementDataSync(value uint8) uint8 {
	if value == 255 {
		return 1
	}
	return value + 1
}

func (s *Store) setDataSyncLocked(value uint8) {
	s.dataSync = value
	setDataSync(s.current, value)
}

func setDataSync(instances map[Key]Instance, value uint8) {
	key := Key{ClassID: me.OnuDataClassID, EntityID: 0}
	instance, exists := instances[key]
	if !exists {
		return
	}
	instance.Attributes[me.OnuData_MibDataSync] = value
	instances[key] = instance
}

func cloneInstances(instances map[Key]Instance) map[Key]Instance {
	cloned := make(map[Key]Instance, len(instances))
	for key, instance := range instances {
		cloned[key] = cloneInstance(instance)
	}
	return cloned
}

func cloneInstancePointer(instance *Instance) *Instance {
	if instance == nil {
		return nil
	}
	cloned := cloneInstance(*instance)
	return &cloned
}

func cloneInstance(instance Instance) Instance {
	instance.Attributes = cloneAttributes(instance.Attributes)
	return instance
}

func cloneAttributes(attributes me.AttributeValueMap) me.AttributeValueMap {
	copy := make(me.AttributeValueMap, len(attributes))
	for name, value := range attributes {
		copy[name] = cloneValue(value)
	}
	return copy
}

func cloneValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case []byte:
		return append([]byte(nil), typed...)
	case []uint16:
		return append([]uint16(nil), typed...)
	case []uint32:
		return append([]uint32(nil), typed...)
	case []uint64:
		return append([]uint64(nil), typed...)
	case me.TableRows:
		return me.TableRows{NumRows: typed.NumRows, Rows: append([]byte(nil), typed.Rows...)}
	default:
		return value
	}
}

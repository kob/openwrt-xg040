// SPDX-License-Identifier: Apache-2.0

package mib

import (
	"fmt"
	"reflect"
	"sort"

	me "github.com/opencord/omci-lib-go/v2/generated"
)

const StateVersion = 1

type State struct {
	Version     uint8           `json:"version"`
	StateDomain string          `json:"state_domain,omitempty"`
	MIBDataSync uint8           `json:"mib_data_sync"`
	Instances   []StateInstance `json:"instances"`
}

type StateInstance struct {
	ClassID    me.ClassID       `json:"class_id"`
	EntityID   uint16           `json:"entity_id"`
	Origin     Origin           `json:"origin"`
	Attributes []StateAttribute `json:"attributes"`
}

type StateAttribute struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Unsigned uint64   `json:"unsigned,omitempty"`
	Octets   []byte   `json:"octets,omitempty"`
	Values   []uint64 `json:"values,omitempty"`
	NumRows  int      `json:"num_rows,omitempty"`
}

func ExportState(snapshot []Instance, dataSync uint8, stateDomain ...string) (State, error) {
	if len(stateDomain) > 1 {
		return State{}, fmt.Errorf("MIB state has multiple compatibility domains")
	}
	state := State{Version: StateVersion, MIBDataSync: dataSync,
		Instances: make([]StateInstance, 0, len(snapshot))}
	if len(stateDomain) == 1 {
		state.StateDomain = stateDomain[0]
	}
	for _, instance := range snapshot {
		encoded := StateInstance{
			ClassID: instance.ClassID, EntityID: instance.EntityID, Origin: instance.Origin,
			Attributes: make([]StateAttribute, 0, len(instance.Attributes)),
		}
		for name, value := range instance.Attributes {
			attribute, err := encodeStateAttribute(name, value)
			if err != nil {
				return State{}, fmt.Errorf("encode ME %v/%#x attribute %s: %w",
					instance.ClassID, instance.EntityID, name, err)
			}
			encoded.Attributes = append(encoded.Attributes, attribute)
		}
		sort.Slice(encoded.Attributes, func(i, j int) bool {
			return encoded.Attributes[i].Name < encoded.Attributes[j].Name
		})
		state.Instances = append(state.Instances, encoded)
	}
	sort.Slice(state.Instances, func(i, j int) bool {
		if state.Instances[i].ClassID == state.Instances[j].ClassID {
			return state.Instances[i].EntityID < state.Instances[j].EntityID
		}
		return state.Instances[i].ClassID < state.Instances[j].ClassID
	})
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s State) Validate() error {
	instances, err := s.decode()
	if err != nil {
		return err
	}
	for _, instance := range instances {
		if instance.ClassID != me.OnuDataClassID || instance.EntityID != 0 {
			continue
		}
		dataSync, valid := instance.Attributes[me.OnuData_MibDataSync].(uint8)
		if !valid || dataSync != s.MIBDataSync {
			return fmt.Errorf("MIB data sync attribute %#v does not match state %d",
				instance.Attributes[me.OnuData_MibDataSync], s.MIBDataSync)
		}
		return nil
	}
	return fmt.Errorf("MIB state has no ONU data ME")
}

func NewFromState(factory []Instance, state State, options Options) (*Store, error) {
	if state.StateDomain != options.StateDomain {
		return nil, fmt.Errorf("MIB state domain %q does not match configured domain %q",
			state.StateDomain, options.StateDomain)
	}
	store, err := NewWithOptions(factory, options)
	if err != nil {
		return nil, err
	}
	restored, err := state.decode()
	if err != nil {
		return nil, err
	}

	current := make(map[Key]Instance, len(restored))
	for _, instance := range restored {
		if _, duplicate := current[instance.Key]; duplicate {
			return nil, fmt.Errorf("duplicate restored ME %v/%#x", instance.ClassID, instance.EntityID)
		}
		normalized, err := store.normalize(instance)
		if err != nil {
			return nil, fmt.Errorf("invalid restored ME %v/%#x: %w",
				instance.ClassID, instance.EntityID, err)
		}
		if !store.supportsClass(instance.ClassID) {
			return nil, fmt.Errorf("restored ME %v/%#x is not supported by this ONU",
				instance.ClassID, instance.EntityID)
		}
		entity, result := loadDefinition(normalized.ClassID, normalized.EntityID, normalized.Attributes)
		if result != nil {
			return nil, result
		}
		if err := store.validateSupportedAttributes(entity, normalized.Attributes); err != nil {
			return nil, fmt.Errorf("restored ME %v/%#x has unsupported attributes: %w",
				instance.ClassID, instance.EntityID, err)
		}
		if instance.Origin == OriginONU {
			factoryInstance, exists := store.factory[instance.Key]
			if !exists {
				return nil, fmt.Errorf("restored ONU-created ME %v/%#x is not in the factory MIB",
					instance.ClassID, instance.EntityID)
			}
			if !sameAttributeNames(factoryInstance.Attributes, normalized.Attributes) {
				return nil, fmt.Errorf("restored ONU-created ME %v/%#x attribute set does not match the factory MIB",
					instance.ClassID, instance.EntityID)
			}
		} else if instance.Origin == OriginOLT {
			definition := normalizedEntityDefinition(normalized)
			if definition == nil ||
				(definition.Access != me.CreatedByOlt && definition.Access != me.CreatedByBoth) {
				return nil, fmt.Errorf("restored OLT-created ME %v/%#x has incompatible access",
					instance.ClassID, instance.EntityID)
			}
		} else {
			return nil, fmt.Errorf("restored ME %v/%#x has invalid origin %d",
				instance.ClassID, instance.EntityID, instance.Origin)
		}
		normalized.Origin = instance.Origin
		current[normalized.Key] = normalized
	}
	for key, factoryInstance := range store.factory {
		instance, exists := current[key]
		if !exists && key.ClassID == me.Onu3GClassID && key.EntityID == 0 {
			current[key] = cloneInstance(factoryInstance)
			continue
		}
		if !exists || instance.Origin != OriginONU {
			return nil, fmt.Errorf("factory ME %v/%#x is missing from restored state", key.ClassID, key.EntityID)
		}
	}
	if err := validateRestoredIdentity(store.factory, current); err != nil {
		return nil, err
	}
	onuData, exists := current[Key{ClassID: me.OnuDataClassID, EntityID: 0}]
	if !exists {
		return nil, fmt.Errorf("restored ONU data ME is missing")
	}
	dataSync, valid := onuData.Attributes[me.OnuData_MibDataSync].(uint8)
	if !valid || dataSync != state.MIBDataSync {
		return nil, fmt.Errorf("restored MIB data sync attribute %#v does not match state %d",
			onuData.Attributes[me.OnuData_MibDataSync], state.MIBDataSync)
	}
	store.current = current
	store.dataSync = dataSync
	return store, nil
}

// RestoreONU3Factory copies only the non-volatile ONU3-G circular-buffer state
// from a persisted MIB document. Service MEs in that document may be stale and
// are deliberately ignored; current identity and capability values come from
// the supplied factory MIB.
func RestoreONU3Factory(factory []Instance, state State, stateDomain ...string) ([]Instance, error) {
	if len(stateDomain) > 1 {
		return nil, fmt.Errorf("ONU3 restore has multiple compatibility domains")
	}
	if len(stateDomain) == 1 && state.StateDomain != stateDomain[0] {
		return nil, fmt.Errorf("MIB state domain %q does not match configured domain %q",
			state.StateDomain, stateDomain[0])
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	restored, err := state.decode()
	if err != nil {
		return nil, err
	}
	factoryMap := make(map[Key]Instance, len(factory))
	for _, instance := range factory {
		factoryMap[instance.Key] = cloneInstance(instance)
	}
	restoredMap := make(map[Key]Instance, len(restored))
	for _, instance := range restored {
		restoredMap[instance.Key] = instance
	}
	if err := validateRestoredIdentity(factoryMap, restoredMap); err != nil {
		return nil, err
	}

	key := Key{ClassID: me.Onu3GClassID, EntityID: 0}
	persisted, present := restoredMap[key]
	current, supported := factoryMap[key]
	if !supported {
		return nil, fmt.Errorf("factory MIB has no ONU3-G ME")
	}
	if !present {
		return snapshotInstances(factoryMap), nil
	}
	if persisted.Origin != OriginONU {
		return nil, fmt.Errorf("persisted ONU3-G ME has origin %d", persisted.Origin)
	}
	persisted, err = normalize(persisted)
	if err != nil {
		return nil, fmt.Errorf("invalid persisted ONU3-G ME: %w", err)
	}
	if persisted.Attributes[me.Onu3G_TotalNumberOfStatusSnapshots] !=
		current.Attributes[me.Onu3G_TotalNumberOfStatusSnapshots] {
		return nil, fmt.Errorf("persisted ONU3-G snapshot capacity does not match this ONU")
	}
	for _, name := range []string{
		me.Onu3G_NumberOfValidStatusSnapshots,
		me.Onu3G_NextStatusSnapshotIndex,
		me.Onu3G_StatusSnapshotRecordTable,
		me.Onu3G_MostRecentStatusSnapshot,
	} {
		current.Attributes[name] = cloneValue(persisted.Attributes[name])
	}
	current, err = normalize(current)
	if err != nil {
		return nil, fmt.Errorf("merge persisted ONU3-G ME: %w", err)
	}
	factoryMap[key] = current
	return snapshotInstances(factoryMap), nil
}

func sameAttributeNames(left, right me.AttributeValueMap) bool {
	if len(left) != len(right) {
		return false
	}
	for name := range left {
		if _, present := right[name]; !present {
			return false
		}
	}
	return true
}

func normalizedEntityDefinition(instance Instance) *me.ManagedEntityDefinition {
	entity, result := loadDefinition(instance.ClassID, instance.EntityID, instance.Attributes)
	if result != nil {
		return nil
	}
	definition := entity.GetManagedEntityDefinition()
	return &definition
}

func validateRestoredIdentity(factory, restored map[Key]Instance) error {
	key := Key{ClassID: me.OnuGClassID, EntityID: 0}
	want, wantOK := factory[key]
	got, gotOK := restored[key]
	if !wantOK || !gotOK {
		return fmt.Errorf("ONU-G identity ME is missing")
	}
	for _, name := range []string{me.OnuG_VendorId, me.OnuG_SerialNumber} {
		if !reflect.DeepEqual(want.Attributes[name], got.Attributes[name]) {
			return fmt.Errorf("restored ONU-G %s does not match configured identity", name)
		}
	}
	return nil
}

func (s State) decode() ([]Instance, error) {
	if s.Version != StateVersion {
		return nil, fmt.Errorf("unsupported MIB state version %d", s.Version)
	}
	if len(s.Instances) == 0 {
		return nil, fmt.Errorf("MIB state contains no managed entities")
	}
	instances := make([]Instance, 0, len(s.Instances))
	seen := make(map[Key]struct{}, len(s.Instances))
	for _, encoded := range s.Instances {
		key := Key{ClassID: encoded.ClassID, EntityID: encoded.EntityID}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate MIB state ME %v/%#x", key.ClassID, key.EntityID)
		}
		seen[key] = struct{}{}
		if encoded.Origin != OriginONU && encoded.Origin != OriginOLT {
			return nil, fmt.Errorf("MIB state ME %v/%#x has invalid origin %d",
				key.ClassID, key.EntityID, encoded.Origin)
		}
		attributes := make(me.AttributeValueMap, len(encoded.Attributes))
		for _, attribute := range encoded.Attributes {
			if attribute.Name == "" {
				return nil, fmt.Errorf("MIB state ME %v/%#x has an unnamed attribute", key.ClassID, key.EntityID)
			}
			if _, duplicate := attributes[attribute.Name]; duplicate {
				return nil, fmt.Errorf("MIB state ME %v/%#x has duplicate attribute %s",
					key.ClassID, key.EntityID, attribute.Name)
			}
			value, err := decodeStateAttribute(attribute)
			if err != nil {
				return nil, fmt.Errorf("decode ME %v/%#x attribute %s: %w",
					key.ClassID, key.EntityID, attribute.Name, err)
			}
			attributes[attribute.Name] = value
		}
		instances = append(instances, Instance{Key: key, Attributes: attributes, Origin: encoded.Origin})
	}
	return instances, nil
}

func encodeStateAttribute(name string, value interface{}) (StateAttribute, error) {
	attribute := StateAttribute{Name: name}
	switch typed := value.(type) {
	case uint8:
		attribute.Kind, attribute.Unsigned = "uint8", uint64(typed)
	case uint16:
		attribute.Kind, attribute.Unsigned = "uint16", uint64(typed)
	case uint32:
		attribute.Kind, attribute.Unsigned = "uint32", uint64(typed)
	case uint64:
		attribute.Kind, attribute.Unsigned = "uint64", typed
	case []byte:
		attribute.Kind, attribute.Octets = "octets", append([]byte(nil), typed...)
	case []uint16:
		attribute.Kind, attribute.Values = "uint16s", unsigned16Values(typed)
	case []uint32:
		attribute.Kind, attribute.Values = "uint32s", unsigned32Values(typed)
	case []uint64:
		attribute.Kind, attribute.Values = "uint64s", append([]uint64(nil), typed...)
	case me.TableRows:
		attribute.Kind, attribute.NumRows = "table", typed.NumRows
		attribute.Octets = append([]byte(nil), typed.Rows...)
	default:
		return StateAttribute{}, fmt.Errorf("unsupported value type %T", value)
	}
	return attribute, nil
}

func decodeStateAttribute(attribute StateAttribute) (interface{}, error) {
	switch attribute.Kind {
	case "uint8":
		if attribute.Unsigned > 0xff {
			return nil, fmt.Errorf("uint8 value %d is out of range", attribute.Unsigned)
		}
		return uint8(attribute.Unsigned), nil
	case "uint16":
		if attribute.Unsigned > 0xffff {
			return nil, fmt.Errorf("uint16 value %d is out of range", attribute.Unsigned)
		}
		return uint16(attribute.Unsigned), nil
	case "uint32":
		if attribute.Unsigned > 0xffffffff {
			return nil, fmt.Errorf("uint32 value %d is out of range", attribute.Unsigned)
		}
		return uint32(attribute.Unsigned), nil
	case "uint64":
		return attribute.Unsigned, nil
	case "octets":
		return append([]byte(nil), attribute.Octets...), nil
	case "uint16s":
		values := make([]uint16, len(attribute.Values))
		for index, value := range attribute.Values {
			if value > 0xffff {
				return nil, fmt.Errorf("uint16 array value %d is out of range", value)
			}
			values[index] = uint16(value)
		}
		return values, nil
	case "uint32s":
		values := make([]uint32, len(attribute.Values))
		for index, value := range attribute.Values {
			if value > 0xffffffff {
				return nil, fmt.Errorf("uint32 array value %d is out of range", value)
			}
			values[index] = uint32(value)
		}
		return values, nil
	case "uint64s":
		return append([]uint64(nil), attribute.Values...), nil
	case "table":
		if attribute.NumRows < 0 {
			return nil, fmt.Errorf("table row count %d is invalid", attribute.NumRows)
		}
		return me.TableRows{NumRows: attribute.NumRows, Rows: append([]byte(nil), attribute.Octets...)}, nil
	default:
		return nil, fmt.Errorf("unsupported value kind %q", attribute.Kind)
	}
}

func unsigned16Values(values []uint16) []uint64 {
	result := make([]uint64, len(values))
	for index, value := range values {
		result[index] = uint64(value)
	}
	return result
}

func unsigned32Values(values []uint32) []uint64 {
	result := make([]uint64, len(values))
	for index, value := range values {
		result[index] = uint64(value)
	}
	return result
}

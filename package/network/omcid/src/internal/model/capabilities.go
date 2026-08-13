// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"sort"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

// XG2010GSupportedClasses is the authoritative list of managed-entity classes
// accepted by this ONU implementation. A generated G.988 definition alone is
// not evidence that the XG2010G backend implements the class.
func XG2010GSupportedClasses(mode pon.Mode) []me.ClassID {
	if err := mode.Validate(); err != nil {
		return nil
	}
	classes := []me.ClassID{
		me.OnuDataClassID,
		me.CardholderClassID,
		me.CircuitPackClassID,
		me.SoftwareImageClassID,
		me.PhysicalPathTerminationPointEthernetUniClassID,
		me.EthernetPerformanceMonitoringHistoryDataClassID,
		me.MacBridgeServiceProfileClassID,
		me.MacBridgePortConfigurationDataClassID,
		me.VlanTaggingOperationConfigurationDataClassID,
		me.VlanTaggingFilterDataClassID,
		me.Ieee8021PMapperServiceProfileClassID,
		me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		me.OnuGClassID,
		me.Onu2GClassID,
		me.Onu3GClassID,
		me.TContClassID,
		me.AniGClassID,
		me.UniGClassID,
		me.GemInterworkingTerminationPointClassID,
		me.GemPortNetworkCtpClassID,
		me.GalEthernetProfileClassID,
		me.PriorityQueueClassID,
		me.TrafficSchedulerClassID,
		me.TrafficDescriptorClassID,
		me.Dot1RateLimiterClassID,
		me.MulticastGemInterworkingTerminationPointClassID,
		me.EthernetPerformanceMonitoringHistoryData3ClassID,
		me.MulticastOperationsProfileClassID,
		me.MulticastSubscriberConfigInfoClassID,
		me.MulticastSubscriberMonitorClassID,
		me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID,
		me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID,
		me.OmciClassID,
		me.ManagedEntityMeClassID,
		me.AttributeMeClassID,
		me.ThresholdData1ClassID,
		me.ThresholdData2ClassID,
		me.FecPerformanceMonitoringHistoryDataClassID,
		me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID,
	}
	if mode == pon.XGSPON {
		classes = append(classes,
			me.XgPonTcPerformanceMonitoringHistoryDataClassID,
			me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID,
			me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID,
		)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	return classes
}

// XG2010GSupportedAttributeMasks returns the exact attribute surface exposed
// through Get/Create/Set and capability MEs. ONU-created classes derive their
// surface from the factory MIB; OLT-created and synthesized classes are audited
// explicitly here so optional generated definitions never become capabilities
// by accident.
func XG2010GSupportedAttributeMasks(mode pon.Mode, factory []mib.Instance) (map[me.ClassID]uint16, error) {
	if err := mode.Validate(); err != nil {
		return nil, err
	}
	classes := XG2010GSupportedClasses(mode)
	masks := make(map[me.ClassID]uint16, len(classes))
	for _, classID := range classes {
		masks[classID] = 0
	}

	for _, instance := range factory {
		if _, supported := masks[instance.ClassID]; !supported {
			return nil, fmt.Errorf("factory ME %v/%#x is outside the XG2010G class policy",
				instance.ClassID, instance.EntityID)
		}
		definitions, omciErr := me.GetAttributesDefinitions(instance.ClassID)
		if omciErr.StatusCode() != me.Success {
			return nil, fmt.Errorf("load factory ME %v attributes: %w",
				instance.ClassID, omciErr.GetError())
		}
		for name := range instance.Attributes {
			if name == me.ManagedEntityID {
				continue
			}
			definition, err := me.GetAttributeDefinitionByName(definitions, name)
			if err != nil {
				return nil, fmt.Errorf("factory ME %v/%#x attribute %s: %w",
					instance.ClassID, instance.EntityID, name, err)
			}
			masks[instance.ClassID] |= definition.Mask
		}
	}

	// Optional attributes without a real platform or live-state implementation
	// are deliberately absent. Mandatory fixed-value attributes remain present
	// and are constrained by XG2010GValidateInstance.
	audited := map[me.ClassID]uint16{
		me.EthernetPerformanceMonitoringHistoryDataClassID:                0xffff,
		me.MacBridgeServiceProfileClassID:                                 0xffc0,
		me.MacBridgePortConfigurationDataClassID:                          0xfe38,
		me.VlanTaggingOperationConfigurationDataClassID:                   0xf800,
		me.VlanTaggingFilterDataClassID:                                   0xe000,
		me.Ieee8021PMapperServiceProfileClassID:                           0xfff8,
		me.ExtendedVlanTaggingOperationConfigurationDataClassID:           0xffc0,
		me.GemInterworkingTerminationPointClassID:                         0xf300,
		me.GemPortNetworkCtpClassID:                                       0xfa80,
		me.GalEthernetProfileClassID:                                      0x8000,
		me.TrafficDescriptorClassID:                                       0xf100,
		me.Dot1RateLimiterClassID:                                         0xf800,
		me.MulticastGemInterworkingTerminationPointClassID:                0xf3c0,
		me.EthernetPerformanceMonitoringHistoryData3ClassID:               0xffff,
		me.MulticastOperationsProfileClassID:                              0xff7f,
		me.MulticastSubscriberConfigInfoClassID:                           0xfe00,
		me.MulticastSubscriberMonitorClassID:                              0xfc00,
		me.EthernetFramePerformanceMonitoringHistoryDataDownstreamClassID: 0xffff,
		me.EthernetFramePerformanceMonitoringHistoryDataUpstreamClassID:   0xffff,
		me.ThresholdData1ClassID:                                          0xfe00,
		me.ThresholdData2ClassID:                                          0xfe00,
		me.FecPerformanceMonitoringHistoryDataClassID:                     0xfe00,
		me.GemPortNetworkCtpPerformanceMonitoringHistoryDataClassID:       0xfc00,
		me.OmciClassID:            0xc000,
		me.ManagedEntityMeClassID: 0xff00,
		me.AttributeMeClassID:     0xff80,
	}
	if mode == pon.XGSPON {
		audited[me.XgPonTcPerformanceMonitoringHistoryDataClassID] = 0xfffe
		audited[me.XgPonDownstreamManagementPerformanceMonitoringHistoryDataClassID] = 0xffff
		audited[me.XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID] = 0xff00
	}
	for classID, mask := range audited {
		if _, supported := masks[classID]; !supported {
			return nil, fmt.Errorf("attribute policy contains unsupported class %v", classID)
		}
		masks[classID] = mask
	}

	for _, classID := range classes {
		entity, omciErr := me.LoadManagedEntityDefinition(classID, me.ParamData{EntityID: 0})
		if omciErr.StatusCode() != me.Success {
			return nil, fmt.Errorf("load supported ME %v: %w", classID, omciErr.GetError())
		}
		definition := entity.GetManagedEntityDefinition()
		if mask := masks[classID]; mask == 0 {
			return nil, fmt.Errorf("supported ME %v has an empty attribute policy", classID)
		} else if unsupported := mask &^ definition.AllowedAttributeMask; unsupported != 0 {
			return nil, fmt.Errorf("supported ME %v mask %#x contains unknown bits %#x",
				classID, mask, unsupported)
		}
		if definition.Access != me.CreatedByOnu {
			if _, explicit := audited[classID]; !explicit {
				return nil, fmt.Errorf("OLT-created ME %v has not been explicitly audited", classID)
			}
		}
	}
	return masks, nil
}

// XG2010GAttributeCapabilities describes fixed values and non-contiguous
// enumerations that are narrower than their generated wire types.
func XG2010GAttributeCapabilities(mode pon.Mode) map[mib.AttributeCapabilityKey]mib.AttributeCapability {
	capabilities := make(map[mib.AttributeCapabilityKey]mib.AttributeCapability)
	bounds := func(classID me.ClassID, name string, lower, upper uint32) {
		capabilities[mib.AttributeCapabilityKey{ClassID: classID, Name: name}] =
			mib.AttributeCapability{LowerLimit: lower, UpperLimit: upper}
	}
	fixed := func(classID me.ClassID, name string, value uint32) {
		bounds(classID, name, value, value)
	}
	enumeration := func(classID me.ClassID, name string, values ...uint16) {
		capabilities[mib.AttributeCapabilityKey{ClassID: classID, Name: name}] =
			mib.AttributeCapability{CodePoints: append([]uint16(nil), values...)}
	}
	sequence := func(first, last uint16) []uint16 {
		values := make([]uint16, int(last-first)+1)
		for index := range values {
			values[index] = first + uint16(index)
		}
		return values
	}
	_ = mode

	fixed(me.AniGClassID, me.AniG_GemBlockLength, 48)
	bounds(me.AniGClassID, me.AniG_SignalFailThreshold, 3, 8)
	bounds(me.AniGClassID, me.AniG_SignalDegradeThreshold, 4, 10)
	enumeration(me.AniGClassID, me.AniG_SrIndication, 1)
	enumeration(me.AniGClassID, me.AniG_PiggybackDbaReporting, 0)
	enumeration(me.AniGClassID, me.AniG_Arc, 0, 1)

	enumeration(me.CardholderClassID, me.Cardholder_ActualPlugInUnitType, 45, 0xf5)
	enumeration(me.CardholderClassID, me.Cardholder_ExpectedPlugInUnitType, 45, 0xf5)

	enumeration(me.CircuitPackClassID, me.CircuitPack_Type, 45, 0xf5)
	enumeration(me.CircuitPackClassID, me.CircuitPack_AdministrativeState, 0, 1)
	enumeration(me.CircuitPackClassID, me.CircuitPack_OperationalState, 0, 1)
	enumeration(me.CircuitPackClassID, me.CircuitPack_BridgedOrIpInd, 0)

	enumeration(me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		me.ExtendedVlanTaggingOperationConfigurationData_AssociationType, 0, 1, 2, 5)
	enumeration(me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		me.ExtendedVlanTaggingOperationConfigurationData_DownstreamMode, sequence(0, 8)...)

	enumeration(me.GemInterworkingTerminationPointClassID,
		me.GemInterworkingTerminationPoint_InterworkingOption, 1, 5)
	enumeration(me.GemInterworkingTerminationPointClassID,
		me.GemInterworkingTerminationPoint_GalLoopbackConfiguration, 0)
	enumeration(me.GemPortNetworkCtpClassID, me.GemPortNetworkCtp_Direction, 1, 2, 3)
	fixed(me.GalEthernetProfileClassID, me.GalEthernetProfile_MaximumGemPayloadSize, 48)

	enumeration(me.MacBridgePortConfigurationDataClassID,
		me.MacBridgePortConfigurationData_TpType, 1, 3, 5, 6)
	enumeration(me.MacBridgePortConfigurationDataClassID,
		me.MacBridgePortConfigurationData_PortSpanningTreeInd, 0, 1)
	for _, name := range []string{
		me.MacBridgeServiceProfile_SpanningTreeInd,
		me.MacBridgeServiceProfile_LearningInd,
		me.MacBridgeServiceProfile_PortBridgingInd,
		me.MacBridgeServiceProfile_UnknownMacAddressDiscard,
	} {
		enumeration(me.MacBridgeServiceProfileClassID, name, 0, 1)
	}
	bounds(me.MacBridgeServiceProfileClassID, me.MacBridgeServiceProfile_MaxAge, 0x0600, 0x2800)
	bounds(me.MacBridgeServiceProfileClassID, me.MacBridgeServiceProfile_HelloTime, 0x0100, 0x0a00)
	bounds(me.MacBridgeServiceProfileClassID, me.MacBridgeServiceProfile_ForwardDelay, 0x0400, 0x1e00)
	bounds(me.MacBridgePortConfigurationDataClassID, me.MacBridgePortConfigurationData_PortPathCost, 1, 0xffff)

	bounds(me.Ieee8021PMapperServiceProfileClassID, me.Ieee8021PMapperServiceProfile_TpType, 0, 1)
	bounds(me.Ieee8021PMapperServiceProfileClassID, me.Ieee8021PMapperServiceProfile_UnmarkedFrameOption, 0, 1)
	bounds(me.Ieee8021PMapperServiceProfileClassID, me.Ieee8021PMapperServiceProfile_DefaultPBitAssumption, 0, 7)

	enumeration(me.MulticastGemInterworkingTerminationPointClassID,
		me.MulticastGemInterworkingTerminationPoint_InterworkingOption, 0, 1, 5)
	enumeration(me.MulticastOperationsProfileClassID,
		me.MulticastOperationsProfile_IgmpVersion, 1, 2, 3, 16, 17)
	enumeration(me.MulticastOperationsProfileClassID,
		me.MulticastOperationsProfile_IgmpFunction, 0, 1, 2)
	enumeration(me.MulticastOperationsProfileClassID,
		me.MulticastOperationsProfile_ImmediateLeave, 0, 1)
	bounds(me.MulticastOperationsProfileClassID,
		me.MulticastOperationsProfile_UpstreamIgmpTagControl, 0, 3)
	bounds(me.MulticastOperationsProfileClassID,
		me.MulticastOperationsProfile_UnauthorizedJoinRequestBehaviour, 0, 1)
	enumeration(me.MulticastSubscriberConfigInfoClassID,
		me.MulticastSubscriberConfigInfo_MeType, 0, 1)
	enumeration(me.MulticastSubscriberMonitorClassID,
		me.MulticastSubscriberMonitor_MeType, 0, 1)
	enumeration(me.MulticastSubscriberConfigInfoClassID,
		me.MulticastSubscriberConfigInfo_BandwidthEnforcement, 0, 1)

	enumeration(me.Onu2GClassID,
		me.Onu2G_OpticalNetworkUnitManagementAndControlChannelOmccVersion, 0xb4)
	enumeration(me.Onu2GClassID, me.Onu2G_SecurityCapability, 1)
	enumeration(me.Onu2GClassID, me.Onu2G_SecurityMode, 1)
	enumeration(me.OnuGClassID, me.OnuG_TrafficManagementOption, 0)
	enumeration(me.OnuGClassID, me.OnuG_BatteryBackup, 0)
	enumeration(me.OnuGClassID, me.OnuG_AdministrativeState, 0, 1)
	enumeration(me.OnuGClassID, me.OnuG_OperationalState, 0, 1)

	for _, name := range []string{
		me.SoftwareImage_IsCommitted,
		me.SoftwareImage_IsActive,
		me.SoftwareImage_IsValid,
	} {
		enumeration(me.SoftwareImageClassID, name, 0, 1)
	}

	for _, name := range []string{
		me.PhysicalPathTerminationPointEthernetUni_ExpectedType,
		me.PhysicalPathTerminationPointEthernetUni_SensedType,
	} {
		enumeration(me.PhysicalPathTerminationPointEthernetUniClassID, name, 0, 47, 49, 50)
	}
	enumeration(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_AutoDetectionConfiguration, 0)
	enumeration(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_AdministrativeState, 0, 1)
	enumeration(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_OperationalState, 0, 1)
	enumeration(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd, 0, 3, 4, 5)
	enumeration(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_BridgedOrIpInd, 0)
	enumeration(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_Arc, 0, 1)
	fixed(me.PhysicalPathTerminationPointEthernetUniClassID,
		me.PhysicalPathTerminationPointEthernetUni_MaxFrameSize, 2000)

	bounds(me.GemPortNetworkCtpClassID, me.GemPortNetworkCtp_PortId, 0, 0x0fff)
	enumeration(me.TContClassID, me.TCont_Policy, 0, 1, 2)
	enumeration(me.TrafficSchedulerClassID, me.TrafficScheduler_Policy, 0, 1, 2)
	enumeration(me.TrafficDescriptorClassID, me.TrafficDescriptor_MeterType, 0, 2)
	enumeration(me.UniGClassID, me.UniG_AdministrativeState, 0, 1)
	enumeration(me.UniGClassID, me.UniG_ManagementCapability, 0)

	enumeration(me.VlanTaggingFilterDataClassID,
		me.VlanTaggingFilterData_ForwardOperation, sequence(0, 0x21)...)
	bounds(me.VlanTaggingFilterDataClassID, me.VlanTaggingFilterData_NumberOfEntries, 0, 12)
	enumeration(me.VlanTaggingOperationConfigurationDataClassID,
		me.VlanTaggingOperationConfigurationData_UpstreamVlanTaggingOperationMode, 0, 1, 2)
	enumeration(me.VlanTaggingOperationConfigurationDataClassID,
		me.VlanTaggingOperationConfigurationData_DownstreamVlanTaggingOperationMode, 0, 1)
	enumeration(me.VlanTaggingOperationConfigurationDataClassID,
		me.VlanTaggingOperationConfigurationData_AssociationType, 0, 2, 3, 5, 10)
	bounds(me.ExtendedVlanTaggingOperationConfigurationDataClassID,
		me.ExtendedVlanTaggingOperationConfigurationData_EnhancedMode, 0, 1)
	bounds(me.Dot1RateLimiterClassID, me.Dot1RateLimiter_TpType, 1, 2)

	return capabilities
}

// XG2010GValidateInstance constrains standard attributes whose valid wire
// values exceed what the fixed EN7581 data path can faithfully implement.
func XG2010GValidateInstance(mode pon.Mode, instance mib.Instance) error {
	if err := mode.Validate(); err != nil {
		return err
	}
	switch instance.ClassID {
	case me.CardholderClassID:
		actual, actualPresent := instance.Attributes[me.Cardholder_ActualPlugInUnitType].(uint8)
		expected, expectedPresent := instance.Attributes[me.Cardholder_ExpectedPlugInUnitType].(uint8)
		if actualPresent && expectedPresent && expected != actual {
			return xg2010gAttributeError(instance.ClassID,
				me.Cardholder_ExpectedPlugInUnitType,
				"expected plug-in type %d does not match fixed integrated equipment type %d",
				expected, actual)
		}
	case me.Onu2GClassID:
		if value, present := instance.Attributes[me.Onu2G_CurrentConnectivityMode].(uint8); present && value != 0 {
			return xg2010gAttributeError(instance.ClassID,
				me.Onu2G_CurrentConnectivityMode,
				"connectivity mode %d is unsupported; XG2010G uses its fixed service graph", value)
		}
	case me.PhysicalPathTerminationPointEthernetUniClassID:
		expected, expectedPresent := instance.Attributes[me.PhysicalPathTerminationPointEthernetUni_ExpectedType].(uint8)
		sensed, sensedPresent := instance.Attributes[me.PhysicalPathTerminationPointEthernetUni_SensedType].(uint8)
		if expectedPresent && sensedPresent && expected != 0 && expected != sensed {
			return xg2010gAttributeError(instance.ClassID,
				me.PhysicalPathTerminationPointEthernetUni_ExpectedType,
				"expected Ethernet type %d does not match fixed port type %d", expected, sensed)
		}
	case me.GalEthernetProfileClassID:
		if value, present := instance.Attributes[me.GalEthernetProfile_MaximumGemPayloadSize].(uint16); present && value != 48 {
			return xg2010gAttributeError(instance.ClassID,
				me.GalEthernetProfile_MaximumGemPayloadSize,
				"maximum GEM payload size %d is unsupported; XG2010G uses 48", value)
		}
	case me.GemInterworkingTerminationPointClassID:
		if value, present := instance.Attributes[me.GemInterworkingTerminationPoint_GalLoopbackConfiguration].(uint8); present && value != 0 {
			return xg2010gAttributeError(instance.ClassID,
				me.GemInterworkingTerminationPoint_GalLoopbackConfiguration,
				"GAL loopback mode %d is unsupported by the EN7581 data path", value)
		}
	case me.TrafficDescriptorClassID:
		if value, present := instance.Attributes[me.TrafficDescriptor_MeterType].(uint8); present && value != 0 && value != 2 {
			return xg2010gAttributeError(instance.ClassID, me.TrafficDescriptor_MeterType,
				"traffic descriptor meter type %d is unsupported; use unspecified or RFC 2698", value)
		}
	case me.TContClassID:
		if value, present := instance.Attributes[me.TCont_Policy].(uint8); present && value != 0 {
			return xg2010gAttributeError(instance.ClassID, me.TCont_Policy,
				"T-CONT policy %d is fixed; configure the associated traffic scheduler", value)
		}
	case me.TrafficSchedulerClassID:
		if value, present := instance.Attributes[me.TrafficScheduler_TContPointer].(uint16); present &&
			value != instance.EntityID {
			return xg2010gAttributeError(instance.ClassID, me.TrafficScheduler_TContPointer,
				"traffic scheduler %#x is fixed to T-CONT %#x", instance.EntityID, instance.EntityID)
		}
		if value, present := instance.Attributes[me.TrafficScheduler_TrafficSchedulerPointer].(uint16); present && value != 0 {
			return xg2010gAttributeError(instance.ClassID,
				me.TrafficScheduler_TrafficSchedulerPointer,
				"traffic scheduler %#x cannot be chained to scheduler %#x", instance.EntityID, value)
		}
	case me.PriorityQueueClassID:
		related, relatedPresent := instance.Attributes[me.PriorityQueue_RelatedPort].(uint32)
		if relatedPresent {
			upstream := instance.EntityID&0x8000 != 0
			queueIndex := instance.EntityID & 0x7fff
			var wantOwner uint16
			var wantPriority uint16
			if upstream {
				wantOwner = uint16(0x8001 + queueIndex/queuesPerPort)
				wantPriority = queueIndex % queuesPerPort
			} else {
				wantOwner = uint16(ethernetCardID + queueIndex/queuesPerPort)
				wantPriority = queueIndex % queuesPerPort
			}
			want := uint32(wantOwner)<<16 | uint32(wantPriority)
			if related != want {
				return xg2010gAttributeError(instance.ClassID, me.PriorityQueue_RelatedPort,
					"priority queue %#x has fixed related port %#x, not %#x",
					instance.EntityID, want, related)
			}
		}
		if scheduler, present := instance.Attributes[me.PriorityQueue_TrafficSchedulerPointer].(uint16); present {
			want := uint16(0)
			if instance.EntityID&0x8000 != 0 {
				want = uint16(0x8001 + (instance.EntityID&0x7fff)/queuesPerPort)
			}
			if scheduler != want {
				return xg2010gAttributeError(instance.ClassID,
					me.PriorityQueue_TrafficSchedulerPointer,
					"priority queue %#x has fixed scheduler %#x, not %#x",
					instance.EntityID, want, scheduler)
			}
		}
	}
	return nil
}

func XG2010GInstanceValidator(mode pon.Mode) func(mib.Instance) error {
	return func(instance mib.Instance) error {
		return XG2010GValidateInstance(mode, instance)
	}
}

func xg2010gAttributeError(classID me.ClassID, name, format string, arguments ...interface{}) error {
	definitions, omciErr := me.GetAttributesDefinitions(classID)
	if omciErr.StatusCode() != me.Success {
		return &mib.ResultError{Result: me.ProcessingError, Cause: omciErr.GetError()}
	}
	definition, err := me.GetAttributeDefinitionByName(definitions, name)
	if err != nil {
		return &mib.ResultError{Result: me.ProcessingError, Cause: err}
	}
	return &mib.ResultError{Result: me.AttributeFailure, FailedMask: definition.Mask,
		Cause: fmt.Errorf(format, arguments...)}
}

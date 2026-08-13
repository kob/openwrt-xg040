// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"strings"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/onu3"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

const (
	aniEntityID       = 0x8001
	ethernetHolderID  = 0x0101
	aniHolderID       = 0x0180
	ethernetCardID    = 0x0101
	aniCardID         = 0x0180
	softwareImageAID  = 0
	softwareImageBID  = 1
	defaultTContCount = 8
	queuesPerPort     = 8
)

var ethernetConfiguration = [...]uint8{
	4, // LAN1: 10G full duplex
	4, // LAN2: 10G full duplex
	5, // LAN3: 2.5G full duplex
	3, // LAN4: 1G full duplex
}

var ethernetSensedType = [...]uint8{
	49, // LAN1: 10GBASE-T
	49, // LAN2: 10GBASE-T
	50, // LAN3: 2.5GBASE-T
	47, // LAN4: 10/100/1000BASE-T
}

type Identity struct {
	SerialNumber  string
	Version       string
	EquipmentID   string
	RestartReason uint8
	PONMode       pon.Mode
}

func XG2010G(identity Identity) ([]mib.Instance, error) {
	if err := identity.PONMode.Validate(); err != nil {
		return nil, err
	}
	serial, err := serialOctets(identity.SerialNumber)
	if err != nil {
		return nil, err
	}
	if identity.Version == "" {
		identity.Version = "OpenWrt"
	}
	if identity.EquipmentID == "" {
		identity.EquipmentID = "XG2010G"
	}

	vendor := serial[:4]
	ponEquipmentID := identity.EquipmentID + " GPON"
	if identity.PONMode == pon.XGSPON {
		ponEquipmentID = identity.EquipmentID + " XGS-PON"
	}
	instances := []mib.Instance{
		instance(me.OnuDataClassID, 0, me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		}),
		instance(me.OnuGClassID, 0, me.AttributeValueMap{
			me.OnuG_VendorId:     cloneBytes(vendor),
			me.OnuG_Version:      octets(identity.Version, 14),
			me.OnuG_SerialNumber: serial,
			// EN7581 meters a T-CONT, not each GEM connection. Advertising
			// option 2 would promise per-connection shaping that it cannot do.
			me.OnuG_TrafficManagementOption: uint8(0),
			me.OnuG_BatteryBackup:           uint8(0),
			me.OnuG_AdministrativeState:     uint8(0),
			me.OnuG_OperationalState:        uint8(0),
		}),
		instance(me.Onu2GClassID, 0, me.AttributeValueMap{
			me.Onu2G_EquipmentId: octets(identity.EquipmentID, 20),
			me.Onu2G_OpticalNetworkUnitManagementAndControlChannelOmccVersion: uint8(0xb4),
			me.Onu2G_VendorProductCode:                                        uint16(0x2010),
			me.Onu2G_SecurityCapability:                                       uint8(1),
			me.Onu2G_SecurityMode:                                             uint8(1),
			me.Onu2G_TotalPriorityQueueNumber:                                 uint16(0),
			me.Onu2G_TotalTrafficSchedulerNumber:                              uint8(0),
			me.Onu2G_Deprecated:                                               uint8(1),
			me.Onu2G_TotalGemPortIdNumber:                                     uint16(256),
			// The backend accepts the standard bridge/mapping MEs directly; it
			// does not implement ONU-wide connectivity-mode switching.
			me.Onu2G_ConnectivityCapability:  uint16(0),
			me.Onu2G_CurrentConnectivityMode: uint8(0),
			// Only traffic-scheduler policy is reconfigurable. Queue ownership,
			// scheduler ownership and T-CONT policy are fixed by the factory MIB.
			me.Onu2G_QualityOfServiceQosConfigurationFlexibility: uint16(0x0008),
			me.Onu2G_PriorityQueueScaleFactor:                    uint16(1),
		}),
		instance(me.Onu3GClassID, 0, me.AttributeValueMap{
			me.Onu3G_LatestRestartReason:          identity.RestartReason,
			me.Onu3G_TotalNumberOfStatusSnapshots: uint16(onu3.SnapshotCapacity),
			me.Onu3G_NumberOfValidStatusSnapshots: uint16(0),
			me.Onu3G_NextStatusSnapshotIndex:      uint16(0),
			me.Onu3G_StatusSnapshotRecordTable:    me.TableRows{},
			me.Onu3G_SnapAction:                   uint8(0),
			me.Onu3G_MostRecentStatusSnapshot:     make([]byte, onu3.RecordSize),
			me.Onu3G_ResetAction:                  uint8(0),
			me.Onu3G_EnhancedMode:                 uint8(1),
		}),
		instance(me.AniGClassID, aniEntityID, me.AttributeValueMap{
			me.AniG_SrIndication:                uint8(1),
			me.AniG_TotalTcontNumber:            uint16(defaultTContCount),
			me.AniG_GemBlockLength:              uint16(48),
			me.AniG_PiggybackDbaReporting:       uint8(0),
			me.AniG_Deprecated:                  uint8(0),
			me.AniG_SignalFailThreshold:         uint8(5),
			me.AniG_SignalDegradeThreshold:      uint8(9),
			me.AniG_Arc:                         uint8(0),
			me.AniG_ArcInterval:                 uint8(0),
			me.AniG_OpticalSignalLevel:          uint16(0),
			me.AniG_LowerOpticalThreshold:       uint8(0xff),
			me.AniG_UpperOpticalThreshold:       uint8(0xff),
			me.AniG_OnuResponseTime:             uint16(35000),
			me.AniG_TransmitOpticalLevel:        uint16(0),
			me.AniG_LowerTransmitPowerThreshold: uint8(0x81),
			me.AniG_UpperTransmitPowerThreshold: uint8(0x81),
		}),
		instance(me.CardholderClassID, ethernetHolderID, me.AttributeValueMap{
			me.Cardholder_ActualPlugInUnitType:   uint8(45),
			me.Cardholder_ExpectedPlugInUnitType: uint8(45),
		}),
		instance(me.CardholderClassID, aniHolderID, me.AttributeValueMap{
			me.Cardholder_ActualPlugInUnitType:   uint8(0xf5),
			me.Cardholder_ExpectedPlugInUnitType: uint8(0xf5),
		}),
		instance(me.CircuitPackClassID, ethernetCardID, me.AttributeValueMap{
			me.CircuitPack_Type:                        uint8(45),
			me.CircuitPack_NumberOfPorts:               uint8(4),
			me.CircuitPack_SerialNumber:                cloneBytes(serial),
			me.CircuitPack_Version:                     octets(identity.Version, 14),
			me.CircuitPack_VendorId:                    cloneBytes(vendor),
			me.CircuitPack_AdministrativeState:         uint8(0),
			me.CircuitPack_OperationalState:            uint8(0),
			me.CircuitPack_BridgedOrIpInd:              uint8(0),
			me.CircuitPack_EquipmentId:                 octets(identity.EquipmentID+" Ethernet", 20),
			me.CircuitPack_TotalTContBufferNumber:      uint8(0),
			me.CircuitPack_TotalPriorityQueueNumber:    uint8(32),
			me.CircuitPack_TotalTrafficSchedulerNumber: uint8(0),
		}),
		instance(me.CircuitPackClassID, aniCardID, me.AttributeValueMap{
			me.CircuitPack_Type:                        uint8(0xf5),
			me.CircuitPack_NumberOfPorts:               uint8(1),
			me.CircuitPack_SerialNumber:                cloneBytes(serial),
			me.CircuitPack_Version:                     octets(identity.Version, 14),
			me.CircuitPack_VendorId:                    cloneBytes(vendor),
			me.CircuitPack_AdministrativeState:         uint8(0),
			me.CircuitPack_OperationalState:            uint8(0),
			me.CircuitPack_EquipmentId:                 octets(ponEquipmentID, 20),
			me.CircuitPack_TotalTContBufferNumber:      uint8(defaultTContCount),
			me.CircuitPack_TotalPriorityQueueNumber:    uint8(defaultTContCount * 8),
			me.CircuitPack_TotalTrafficSchedulerNumber: uint8(defaultTContCount),
		}),
		softwareImage(softwareImageAID, identity.Version, true, true),
		softwareImage(softwareImageBID, "standby", false, false),
	}

	for index := 0; index < defaultTContCount; index++ {
		entityID := uint16(0x8001 + index)
		instances = append(instances, instance(me.TContClassID, entityID, me.AttributeValueMap{
			me.TCont_AllocId: uint16(0xffff),
			me.TCont_Policy:  uint8(0),
		}), instance(me.TrafficSchedulerClassID, entityID, me.AttributeValueMap{
			me.TrafficScheduler_TContPointer:            entityID,
			me.TrafficScheduler_TrafficSchedulerPointer: uint16(0),
			me.TrafficScheduler_Policy:                  uint8(1),
			me.TrafficScheduler_PriorityWeight:          uint8(0),
		}))
		for priority := 0; priority < queuesPerPort; priority++ {
			queueID := uint16(0x8000 + index*queuesPerPort + priority)
			instances = append(instances, priorityQueue(queueID, entityID, entityID, priority))
		}
	}

	for port := 1; port <= len(ethernetConfiguration); port++ {
		entityID := uint16(ethernetCardID + port - 1)
		instances = append(instances,
			instance(me.PhysicalPathTerminationPointEthernetUniClassID, entityID, me.AttributeValueMap{
				me.PhysicalPathTerminationPointEthernetUni_ExpectedType:               uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_SensedType:                 ethernetSensedType[port-1],
				me.PhysicalPathTerminationPointEthernetUni_AutoDetectionConfiguration: uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_AdministrativeState:        uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_OperationalState:           uint8(1),
				me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd:           ethernetConfiguration[port-1],
				me.PhysicalPathTerminationPointEthernetUni_MaxFrameSize:               uint16(2000),
				me.PhysicalPathTerminationPointEthernetUni_BridgedOrIpInd:             uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_Arc:                        uint8(0),
				me.PhysicalPathTerminationPointEthernetUni_ArcInterval:                uint8(0),
			}),
			instance(me.UniGClassID, entityID, me.AttributeValueMap{
				me.UniG_Deprecated:           uint16(0),
				me.UniG_AdministrativeState:  uint8(0),
				me.UniG_ManagementCapability: uint8(0),
			}),
		)
		for priority := 0; priority < queuesPerPort; priority++ {
			queueID := uint16((port-1)*queuesPerPort + priority)
			instances = append(instances, priorityQueue(queueID, entityID, 0, priority))
		}
	}

	return instances, nil
}

func priorityQueue(entityID, relatedEntity, scheduler uint16, priority int) mib.Instance {
	return instance(me.PriorityQueueClassID, entityID, me.AttributeValueMap{
		me.PriorityQueue_QueueConfigurationOption: uint8(0),
		me.PriorityQueue_MaximumQueueSize:         uint16(4096),
		me.PriorityQueue_AllocatedQueueSize:       uint16(4096),
		me.PriorityQueue_RelatedPort:              uint32(relatedEntity)<<16 | uint32(priority),
		me.PriorityQueue_TrafficSchedulerPointer:  scheduler,
		me.PriorityQueue_Weight:                   uint8(1),
	})
}

func instance(classID me.ClassID, entityID uint16, attributes me.AttributeValueMap) mib.Instance {
	return mib.Instance{
		Key:        mib.Key{ClassID: classID, EntityID: entityID},
		Attributes: attributes,
		Origin:     mib.OriginONU,
	}
}

func softwareImage(entityID uint16, version string, active, valid bool) mib.Instance {
	flag := uint8(0)
	if active {
		flag = 1
	}
	validFlag := uint8(0)
	if valid {
		validFlag = 1
	}
	return instance(me.SoftwareImageClassID, entityID, me.AttributeValueMap{
		me.SoftwareImage_Version:     octets(version, 14),
		me.SoftwareImage_IsCommitted: flag,
		me.SoftwareImage_IsActive:    flag,
		me.SoftwareImage_IsValid:     validFlag,
		me.SoftwareImage_ProductCode: octets("XG2010G", 25),
		me.SoftwareImage_ImageHash:   make([]byte, 16),
	})
}

func serialOctets(value string) ([]byte, error) {
	if len(value) != 12 {
		return nil, fmt.Errorf("serial number must be four vendor characters followed by eight hexadecimal digits")
	}
	serial := make([]byte, 8)
	copy(serial, value[:4])
	for index := 0; index < 4; index++ {
		var octet uint8
		if _, err := fmt.Sscanf(value[4+index*2:6+index*2], "%02x", &octet); err != nil {
			return nil, fmt.Errorf("invalid serial number %q: %w", value, err)
		}
		serial[4+index] = octet
	}
	return serial, nil
}

func octets(value string, size int) []byte {
	result := make([]byte, size)
	copy(result, []byte(strings.TrimSpace(value)))
	return result
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

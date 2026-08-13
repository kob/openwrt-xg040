// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/vlan"
)

const nullPointer = 0xffff

var mapperPBitAttributes = [...]string{
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority0,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority1,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority2,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority3,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority4,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority5,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority6,
	me.Ieee8021PMapperServiceProfile_InterworkTpPointerForPBitPriority7,
}

type ServiceGraph struct {
	UNIs                  []EthernetUNI                   `json:"unis"`
	TCONTs                []TCONT                         `json:"tconts"`
	TrafficDescs          []TrafficDescriptor             `json:"traffic_descriptors"`
	Dot1RateLimiters      []Dot1RateLimiter               `json:"dot1_rate_limiters"`
	GEMPorts              []GEMPort                       `json:"gem_ports"`
	Interworking          []GEMInterworking               `json:"gem_interworking"`
	MulticastInterworking []MulticastGEMInterworking      `json:"multicast_gem_interworking"`
	MulticastProfiles     []MulticastOperationsProfile    `json:"multicast_operations_profiles"`
	MulticastSubscribers  []MulticastSubscriberConfigInfo `json:"multicast_subscribers"`
	Mappers               []PBitMapper                    `json:"pbit_mappers"`
	Bridges               []MACBridge                     `json:"bridges"`
	VLANFilters           []VLANFilter                    `json:"vlan_filters"`
	VLANOperations        []VLANOperation                 `json:"vlan_operations"`
	ExtendedVLANs         []ExtendedVLAN                  `json:"extended_vlans"`
}

type EthernetUNI struct {
	EntityID            uint16 `json:"entity_id"`
	Interface           string `json:"interface"`
	AdministrativeState uint8  `json:"administrative_state"`
	OperationalState    uint8  `json:"operational_state"`
	Configuration       uint8  `json:"configuration"`
}

type TCONT struct {
	EntityID        uint16    `json:"entity_id"`
	AllocID         uint16    `json:"alloc_id"`
	SchedulerPolicy uint8     `json:"scheduler_policy"`
	SchedulerWeight uint8     `json:"scheduler_weight"`
	QueueEntities   [8]uint16 `json:"queue_entities"`
	QueueWeights    [8]uint8  `json:"queue_weights"`
}

type GEMPort struct {
	EntityID        uint16 `json:"entity_id"`
	PortID          uint16 `json:"port_id"`
	TCONT           uint16 `json:"tcont"`
	AllocID         uint16 `json:"alloc_id"`
	Direction       uint8  `json:"direction"`
	UpstreamQueue   uint16 `json:"upstream_queue"`
	DownstreamQueue uint16 `json:"downstream_queue"`
	UpstreamTD      uint16 `json:"upstream_traffic_descriptor"`
	DownstreamTD    uint16 `json:"downstream_traffic_descriptor"`
}

// TrafficDescriptor is the normalized class-280 ME consumed by a native
// GPON/QDMA backend. Rates and burst sizes retain the G.988 wire values; the
// backend is responsible for converting them to the hardware tick units.
type TrafficDescriptor struct {
	EntityID             uint16 `json:"entity_id"`
	CIR                  uint32 `json:"cir"`
	PIR                  uint32 `json:"pir"`
	CBS                  uint32 `json:"cbs"`
	PBS                  uint32 `json:"pbs"`
	ColourMode           uint8  `json:"colour_mode"`
	IngressColourMarking uint8  `json:"ingress_colour_marking"`
	EgressColourMarking  uint8  `json:"egress_colour_marking"`
	MeterType            uint8  `json:"meter_type"`
}

// Dot1RateLimiter is the normalized class-298 association. Traffic descriptor
// pointers retain 0xffff for an administratively unlimited traffic category.
type Dot1RateLimiter struct {
	EntityID                   uint16 `json:"entity_id"`
	ParentME                   uint16 `json:"parent_me"`
	TPType                     uint8  `json:"tp_type"`
	UpstreamUnicastFloodTD     uint16 `json:"upstream_unicast_flood_traffic_descriptor"`
	UpstreamBroadcastTD        uint16 `json:"upstream_broadcast_traffic_descriptor"`
	UpstreamMulticastPayloadTD uint16 `json:"upstream_multicast_payload_traffic_descriptor"`
}

type GEMInterworking struct {
	EntityID                uint16 `json:"entity_id"`
	GEMPort                 uint16 `json:"gem_port"`
	Option                  uint8  `json:"option"`
	ServiceProfile          uint16 `json:"service_profile"`
	InterworkingTermination uint16 `json:"interworking_termination"`
	GALProfile              uint16 `json:"gal_profile"`
}

type MulticastGEMInterworking struct {
	EntityID       uint16               `json:"entity_id"`
	GEMPort        uint16               `json:"gem_port"`
	PortID         uint16               `json:"port_id"`
	TCONT          uint16               `json:"tcont"`
	AllocID        uint16               `json:"alloc_id"`
	Option         uint8                `json:"option"`
	ServiceProfile uint16               `json:"service_profile"`
	GALProfile     uint16               `json:"gal_profile"`
	IPv4Ranges     []MulticastIPv4Range `json:"ipv4_ranges"`
	IPv6Ranges     []MulticastIPv6Range `json:"ipv6_ranges"`
}

type MulticastIPv4Range struct {
	GEMPortID    uint16 `json:"gem_port_id"`
	SecondaryKey uint16 `json:"secondary_key"`
	Start        string `json:"start"`
	Stop         string `json:"stop"`
}

type MulticastIPv6Range struct {
	GEMPortID    uint16 `json:"gem_port_id"`
	SecondaryKey uint16 `json:"secondary_key"`
	Start        string `json:"start"`
	Stop         string `json:"stop"`
}

type MulticastOperationsProfile struct {
	EntityID                  uint16              `json:"entity_id"`
	IGMPVersion               uint8               `json:"igmp_version"`
	IGMPFunction              uint8               `json:"igmp_function"`
	ImmediateLeave            uint8               `json:"immediate_leave"`
	UpstreamTCI               uint16              `json:"upstream_tci"`
	UpstreamTagControl        uint8               `json:"upstream_tag_control"`
	UpstreamRate              uint32              `json:"upstream_rate"`
	DynamicACL                []MulticastACLEntry `json:"dynamic_acl"`
	StaticACL                 []MulticastACLEntry `json:"static_acl"`
	Robustness                uint8               `json:"robustness"`
	QuerierIPAddress          uint32              `json:"querier_ip_address"`
	QueryInterval             uint32              `json:"query_interval"`
	QueryMaxResponseTime      uint32              `json:"query_max_response_time"`
	LastMemberQueryInterval   uint32              `json:"last_member_query_interval"`
	UnauthorizedJoinBehaviour uint8               `json:"unauthorized_join_behaviour"`
	DownstreamTagControl      uint8               `json:"downstream_tag_control"`
	DownstreamTCI             uint16              `json:"downstream_tci"`
}

type MulticastACLEntry struct {
	RowKey             uint16 `json:"row_key"`
	IPVersion          uint8  `json:"ip_version"`
	GEMPortID          uint16 `json:"gem_port_id"`
	VLANID             uint16 `json:"vlan_id"`
	Source             string `json:"source"`
	Start              string `json:"start"`
	Stop               string `json:"stop"`
	ImputedBandwidth   uint32 `json:"imputed_bandwidth"`
	PreviewLength      uint16 `json:"preview_length"`
	PreviewRepeatTime  uint16 `json:"preview_repeat_time"`
	PreviewRepeatCount uint16 `json:"preview_repeat_count"`
	PreviewResetTime   uint16 `json:"preview_reset_time"`
}

type MulticastSubscriberConfigInfo struct {
	EntityID              uint16                    `json:"entity_id"`
	METype                uint8                     `json:"me_type"`
	Profile               uint16                    `json:"profile"`
	MaxSimultaneousGroups uint16                    `json:"max_simultaneous_groups"`
	MaxMulticastBandwidth uint32                    `json:"max_multicast_bandwidth"`
	BandwidthEnforcement  uint8                     `json:"bandwidth_enforcement"`
	ServicePackages       []MulticastServicePackage `json:"service_packages"`
	AllowedPreviewGroups  []AllowedPreviewGroup     `json:"allowed_preview_groups"`
}

type MulticastServicePackage struct {
	RowKey                uint16 `json:"row_key"`
	VLANID                uint16 `json:"vlan_id"`
	MaxSimultaneousGroups uint16 `json:"max_simultaneous_groups"`
	MaxMulticastBandwidth uint32 `json:"max_multicast_bandwidth"`
	OperationsProfile     uint16 `json:"operations_profile"`
}

type AllowedPreviewGroup struct {
	RowKey      uint16 `json:"row_key"`
	IPVersion   uint8  `json:"ip_version"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ANIVLAN     uint16 `json:"ani_vlan"`
	UNIVLAN     uint16 `json:"uni_vlan"`
	Duration    uint16 `json:"duration_minutes"`
	TimeLeft    uint16 `json:"time_left_minutes"`
}

type PBitMapper struct {
	EntityID            uint16    `json:"entity_id"`
	TPType              uint8     `json:"tp_type"`
	TPPointer           uint16    `json:"tp_pointer"`
	PBits               [8]uint16 `json:"pbits"`
	UnmarkedFrameOption uint8     `json:"unmarked_frame_option"`
	DefaultPBit         uint8     `json:"default_pbit"`
	DSCPToPBit          [64]uint8 `json:"dscp_to_pbit"`
}

type MACBridge struct {
	EntityID                uint16          `json:"entity_id"`
	SpanningTree            uint8           `json:"spanning_tree"`
	Learning                uint8           `json:"learning"`
	PortBridging            uint8           `json:"port_bridging"`
	Priority                uint16          `json:"priority"`
	MaxAge                  uint16          `json:"max_age_256ths"`
	HelloTime               uint16          `json:"hello_time_256ths"`
	ForwardDelay            uint16          `json:"forward_delay_256ths"`
	UnknownMACDiscard       uint8           `json:"unknown_mac_discard"`
	MACLearningDepth        uint8           `json:"mac_learning_depth"`
	DynamicFilteringAgeTime uint32          `json:"dynamic_filtering_age_time_seconds"`
	Ports                   []MACBridgePort `json:"ports"`
}

type MACBridgePort struct {
	EntityID         uint16 `json:"entity_id"`
	Port             uint8  `json:"port"`
	TPType           uint8  `json:"tp_type"`
	TP               uint16 `json:"tp"`
	Priority         uint16 `json:"priority"`
	PathCost         uint16 `json:"path_cost"`
	SpanningTree     uint8  `json:"spanning_tree"`
	OutboundTD       uint16 `json:"outbound_td"`
	InboundTD        uint16 `json:"inbound_td"`
	MACLearningDepth uint8  `json:"mac_learning_depth"`
}

type VLANFilter struct {
	EntityID         uint16              `json:"entity_id"`
	BridgePort       uint16              `json:"bridge_port"`
	ForwardOperation uint8               `json:"forward_operation"`
	TaggedAction     VLANFilterAction    `json:"tagged_action"`
	TaggedCriterion  VLANFilterCriterion `json:"tagged_criterion"`
	UntaggedAction   VLANFilterAction    `json:"untagged_action"`
	Entries          []uint16            `json:"entries"`
}

type VLANFilterAction string

const (
	VLANFilterActionBridge     VLANFilterAction = "a"
	VLANFilterActionDiscard    VLANFilterAction = "c"
	VLANFilterActionNegative   VLANFilterAction = "g"
	VLANFilterActionPositive   VLANFilterAction = "h"
	VLANFilterActionPositiveDA VLANFilterAction = "j"
)

type VLANFilterCriterion string

const (
	VLANFilterCriterionNone     VLANFilterCriterion = "none"
	VLANFilterCriterionVID      VLANFilterCriterion = "vid"
	VLANFilterCriterionPriority VLANFilterCriterion = "priority"
	VLANFilterCriterionTCI      VLANFilterCriterion = "tci"
)

type ExtendedVLAN struct {
	EntityID        uint16      `json:"entity_id"`
	AssociationType uint8       `json:"association_type"`
	AssociatedClass me.ClassID  `json:"associated_class"`
	AssociatedME    uint16      `json:"associated_me"`
	InputTPID       uint16      `json:"input_tpid"`
	OutputTPID      uint16      `json:"output_tpid"`
	DownstreamMode  uint8       `json:"downstream_mode"`
	EnhancedMode    uint8       `json:"enhanced_mode"`
	DSCPToPBit      [64]uint8   `json:"dscp_to_pbit"`
	Rules           []vlan.Rule `json:"rules"`
}

type VLANOperation struct {
	EntityID        uint16     `json:"entity_id"`
	AssociationType uint8      `json:"association_type"`
	AssociatedClass me.ClassID `json:"associated_class"`
	AssociatedME    uint16     `json:"associated_me"`
	UpstreamMode    uint8      `json:"upstream_mode"`
	UpstreamTCI     uint16     `json:"upstream_tci"`
	DownstreamMode  uint8      `json:"downstream_mode"`
}

// ValidateServiceGraph rejects mutations that would leave hardware-facing
// Ethernet service references ambiguous or dangling.
func ValidateServiceGraph(snapshot []mib.Instance) error {
	_, err := BuildServiceGraph(snapshot)
	return err
}

// BuildServiceGraph resolves the OMCI MIB into the connectivity needed by an
// Airoha backend. Null mapper branches remain present as 0xffff so the OLT can
// construct a service over several transactions.
func BuildServiceGraph(snapshot []mib.Instance) (ServiceGraph, error) {
	instances := make(map[mib.Key]mib.Instance, len(snapshot))
	for _, instance := range snapshot {
		if _, exists := instances[instance.Key]; exists {
			return ServiceGraph{}, fmt.Errorf("duplicate managed entity %d/%#x", instance.ClassID, instance.EntityID)
		}
		instances[instance.Key] = instance
	}

	graph := ServiceGraph{}
	tconts := make(map[uint16]TCONT)
	activeAllocIDs := make(map[uint16]uint16)
	unis := make(map[uint16]EthernetUNI)
	bridges := make(map[uint16]*MACBridge)
	mappers := make(map[uint16]PBitMapper)
	gemPorts := make(map[uint16]GEMPort)
	gemInterworking := make(map[uint16]GEMInterworking)
	multicastInterworking := make(map[uint16]MulticastGEMInterworking)
	multicastProfiles := make(map[uint16]MulticastOperationsProfile)
	tcontIndexes := make(map[uint16]int)

	trafficManagementOption := uint8(0)
	onuAdministrativeState := uint8(0)
	if onu, found := instances[mib.Key{ClassID: me.OnuGClassID, EntityID: 0}]; found {
		var err error
		trafficManagementOption, err = uint8AttributeDefault(onu, me.OnuG_TrafficManagementOption, 0)
		if err != nil {
			return ServiceGraph{}, err
		}
		if trafficManagementOption > 2 {
			return ServiceGraph{}, fmt.Errorf("ONU-G has invalid traffic management option %d", trafficManagementOption)
		}
		onuAdministrativeState, err = administrativeState(onu, me.OnuG_AdministrativeState)
		if err != nil {
			return ServiceGraph{}, err
		}
	}
	circuitPackStates, err := circuitPackAdministrativeStates(instances)
	if err != nil {
		return ServiceGraph{}, err
	}

	for _, instance := range snapshot {
		switch instance.ClassID {
		case me.PhysicalPathTerminationPointEthernetUniClassID:
			interfaceName, err := ethernetUNIInterface(instance.EntityID)
			if err != nil {
				return ServiceGraph{}, err
			}
			administrative, err := uint8AttributeDefault(instance,
				me.PhysicalPathTerminationPointEthernetUni_AdministrativeState, 0)
			if err != nil {
				return ServiceGraph{}, err
			}
			if administrative > 1 {
				return ServiceGraph{}, fmt.Errorf("Ethernet UNI %#x has invalid administrative state %d",
					instance.EntityID, administrative)
			}
			if uniG, found := instances[mib.Key{ClassID: me.UniGClassID, EntityID: instance.EntityID}]; found {
				uniGAdministrative, stateErr := administrativeState(uniG, me.UniG_AdministrativeState)
				if stateErr != nil {
					return ServiceGraph{}, stateErr
				}
				if uniGAdministrative == 1 {
					administrative = 1
				}
			}
			if circuitPackStates[uint8(instance.EntityID>>8)] == 1 ||
				onuAdministrativeState == 1 {
				administrative = 1
			}
			operational, err := uint8AttributeDefault(instance,
				me.PhysicalPathTerminationPointEthernetUni_OperationalState, 1)
			if err != nil {
				return ServiceGraph{}, err
			}
			configuration, err := uint8AttributeDefault(instance,
				me.PhysicalPathTerminationPointEthernetUni_ConfigurationInd, 0)
			if err != nil {
				return ServiceGraph{}, err
			}
			uni := EthernetUNI{EntityID: instance.EntityID, Interface: interfaceName,
				AdministrativeState: administrative, OperationalState: operational,
				Configuration: configuration}
			unis[instance.EntityID] = uni
			graph.UNIs = append(graph.UNIs, uni)

		case me.TContClassID:
			allocID, err := uint16Attribute(instance, me.TCont_AllocId)
			if err != nil {
				return ServiceGraph{}, err
			}
			if allocID != nullPointer && allocID > 0x0fff {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x has out-of-range Alloc-ID %d", instance.EntityID, allocID)
			}
			if previous, duplicate := activeAllocIDs[allocID]; allocID != nullPointer && duplicate {
				return ServiceGraph{}, fmt.Errorf("Alloc-ID %d is shared by T-CONT %#x and %#x", allocID, previous, instance.EntityID)
			}
			if allocID != nullPointer {
				activeAllocIDs[allocID] = instance.EntityID
			}
			policy, err := uint8AttributeDefault(instance, me.TCont_Policy, 0)
			if err != nil {
				return ServiceGraph{}, err
			}
			if policy > 2 {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x uses unsupported scheduler policy %d",
					instance.EntityID, policy)
			}
			tcont := TCONT{EntityID: instance.EntityID, AllocID: allocID,
				SchedulerPolicy: policy}
			tconts[instance.EntityID] = tcont
			tcontIndexes[instance.EntityID] = len(graph.TCONTs)
			graph.TCONTs = append(graph.TCONTs, tcont)

		case me.MacBridgeServiceProfileClassID:
			bridge, err := buildMACBridge(instance)
			if err != nil {
				return ServiceGraph{}, err
			}
			bridges[instance.EntityID] = bridge

		case me.Ieee8021PMapperServiceProfileClassID:
			mapper, err := buildMapper(instance)
			if err != nil {
				return ServiceGraph{}, err
			}
			mappers[instance.EntityID] = mapper
			graph.Mappers = append(graph.Mappers, mapper)

		case me.MulticastOperationsProfileClassID:
			profile, err := buildMulticastOperationsProfile(instance)
			if err != nil {
				return ServiceGraph{}, err
			}
			multicastProfiles[instance.EntityID] = profile
			graph.MulticastProfiles = append(graph.MulticastProfiles, profile)
		}
	}

	// Resolve the T-CONT scheduler and its eight hardware-facing queues after
	// all factory and OLT-created MEs are visible. Ethernet UNI queues are
	// intentionally excluded: their QDMA block is independent from GPON WAN.
	for tcontID, tcont := range tconts {
		var schedulerID uint16
		schedulerFound := false
		for _, instance := range snapshot {
			if instance.ClassID != me.TrafficSchedulerClassID {
				continue
			}
			pointer, err := uint16AttributeDefault(instance,
				me.TrafficScheduler_TContPointer, nullPointer)
			if err != nil {
				return ServiceGraph{}, err
			}
			if pointer != tcontID {
				continue
			}
			if schedulerFound {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x is served by traffic schedulers %#x and %#x",
					tcontID, schedulerID, instance.EntityID)
			}
			policy, err := uint8AttributeDefault(instance,
				me.TrafficScheduler_Policy, tcont.SchedulerPolicy)
			if err != nil {
				return ServiceGraph{}, err
			}
			weight, err := uint8AttributeDefault(instance,
				me.TrafficScheduler_PriorityWeight, 0)
			if err != nil {
				return ServiceGraph{}, err
			}
			if policy > 2 {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x uses unsupported scheduler policy %d",
					tcontID, policy)
			}
			tcont.SchedulerPolicy = policy
			tcont.SchedulerWeight = weight
			schedulerID = instance.EntityID
			schedulerFound = true
		}
		var queueSlots [8]bool
		for _, instance := range snapshot {
			if instance.ClassID != me.PriorityQueueClassID {
				continue
			}
			related, err := uint32AttributeDefault(instance,
				me.PriorityQueue_RelatedPort, 0xffffffff)
			if err != nil {
				return ServiceGraph{}, err
			}
			if uint16(related>>16) != tcontID {
				continue
			}
			priority := uint8(related & 0xff)
			if priority >= 8 {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x priority queue %#x has invalid priority %d",
					tcontID, instance.EntityID, priority)
			}
			if queueSlots[priority] {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x has more than one priority queue at priority %d",
					tcontID, priority)
			}
			queueScheduler, err := uint16AttributeDefault(instance,
				me.PriorityQueue_TrafficSchedulerPointer, 0)
			if err != nil {
				return ServiceGraph{}, err
			}
			if queueScheduler != 0 {
				scheduler, exists := instances[mib.Key{ClassID: me.TrafficSchedulerClassID,
					EntityID: queueScheduler}]
				if !exists {
					return ServiceGraph{}, fmt.Errorf("priority queue %#x references missing traffic scheduler %#x",
						instance.EntityID, queueScheduler)
				}
				schedulerTCONT, err := uint16AttributeDefault(scheduler,
					me.TrafficScheduler_TContPointer, nullPointer)
				if err != nil {
					return ServiceGraph{}, err
				}
				if schedulerTCONT != tcontID {
					return ServiceGraph{}, fmt.Errorf("priority queue %#x scheduler %#x serves T-CONT %#x, not %#x",
						instance.EntityID, queueScheduler, schedulerTCONT, tcontID)
				}
			}
			queueWeight, err := uint8AttributeDefault(instance,
				me.PriorityQueue_Weight, 1)
			if err != nil {
				return ServiceGraph{}, err
			}
			tcont.QueueEntities[priority] = instance.EntityID
			tcont.QueueWeights[priority] = queueWeight
			queueSlots[priority] = true
		}
		if tcont.SchedulerPolicy == 2 {
			haveWeight := false
			for priority := range tcont.QueueWeights {
				haveWeight = haveWeight || tcont.QueueWeights[priority] != 0
			}
			if !haveWeight {
				return ServiceGraph{}, fmt.Errorf("T-CONT %#x WRR scheduler has no non-zero queue weight", tcontID)
			}
		}
		if index, ok := tcontIndexes[tcontID]; ok {
			graph.TCONTs[index] = tcont
		}
	}

	for _, instance := range snapshot {
		if instance.ClassID != me.TrafficDescriptorClassID {
			continue
		}
		descriptor, err := buildTrafficDescriptor(instance)
		if err != nil {
			return ServiceGraph{}, err
		}
		graph.TrafficDescs = append(graph.TrafficDescs, descriptor)
	}

	rateLimiterParents := make(map[mib.Key]uint16)
	for _, instance := range snapshot {
		if instance.ClassID != me.Dot1RateLimiterClassID {
			continue
		}
		limiter, parent, err := buildDot1RateLimiter(instance, instances)
		if err != nil {
			return ServiceGraph{}, err
		}
		if previous, duplicate := rateLimiterParents[parent]; duplicate {
			return ServiceGraph{}, fmt.Errorf("dot1 rate limiters %#x and %#x share parent %d/%#x",
				previous, instance.EntityID, parent.ClassID, parent.EntityID)
		}
		rateLimiterParents[parent] = instance.EntityID
		graph.Dot1RateLimiters = append(graph.Dot1RateLimiters, limiter)
	}

	gemPortIDs := make(map[uint16]uint16)
	for _, instance := range snapshot {
		if instance.ClassID != me.GemPortNetworkCtpClassID {
			continue
		}
		portID, err := uint16Attribute(instance, me.GemPortNetworkCtp_PortId)
		if err != nil {
			return ServiceGraph{}, err
		}
		if portID > 0x0fff {
			return ServiceGraph{}, fmt.Errorf("GEM CTP %#x has out-of-range port ID %d", instance.EntityID, portID)
		}
		if previous, duplicate := gemPortIDs[portID]; duplicate {
			return ServiceGraph{}, fmt.Errorf("GEM port ID %d cannot be mapped by XG2010G CTPs %#x and %#x", portID, previous, instance.EntityID)
		}
		gemPortIDs[portID] = instance.EntityID

		tcontID, err := uint16Attribute(instance, me.GemPortNetworkCtp_TContPointer)
		if err != nil {
			return ServiceGraph{}, err
		}
		tcont, exists := tconts[tcontID]
		if !exists {
			return ServiceGraph{}, fmt.Errorf("GEM CTP %#x references missing T-CONT %#x", instance.EntityID, tcontID)
		}
		direction, err := uint8Attribute(instance, me.GemPortNetworkCtp_Direction)
		if err != nil {
			return ServiceGraph{}, err
		}
		if direction < 1 || direction > 3 {
			return ServiceGraph{}, fmt.Errorf("GEM CTP %#x has invalid direction %d", instance.EntityID, direction)
		}
		upstreamQueue, err := uint16Attribute(instance, me.GemPortNetworkCtp_TrafficManagementPointerForUpstream)
		if err != nil {
			return ServiceGraph{}, err
		}
		if err := validateUpstreamTrafficPointer(instances, instance.EntityID, tcontID,
			upstreamQueue, trafficManagementOption); err != nil {
			return ServiceGraph{}, err
		}
		downstreamQueue, err := uint16Attribute(instance, me.GemPortNetworkCtp_PriorityQueuePointerForDownStream)
		if err != nil {
			return ServiceGraph{}, err
		}
		if downstreamQueue != nullPointer && !hasInstance(instances, me.PriorityQueueClassID, downstreamQueue) {
			return ServiceGraph{}, fmt.Errorf("GEM CTP %#x references missing downstream priority queue %#x", instance.EntityID, downstreamQueue)
		}
		upstreamTD, err := uint16AttributeDefault(instance,
			me.GemPortNetworkCtp_TrafficDescriptorProfilePointerForUpstream, nullPointer)
		if err != nil {
			return ServiceGraph{}, err
		}
		downstreamTD, err := uint16AttributeDefault(instance,
			me.GemPortNetworkCtp_TrafficDescriptorProfilePointerForDownstream, nullPointer)
		if err != nil {
			return ServiceGraph{}, err
		}
		if err := validateTrafficDescriptorPointer(instances, instance.EntityID,
			"upstream", upstreamTD); err != nil {
			return ServiceGraph{}, err
		}
		if err := validateTrafficDescriptorPointer(instances, instance.EntityID,
			"downstream", downstreamTD); err != nil {
			return ServiceGraph{}, err
		}
		gemPort := GEMPort{EntityID: instance.EntityID, PortID: portID, TCONT: tcontID,
			AllocID: tcont.AllocID, Direction: direction, UpstreamQueue: upstreamQueue,
			DownstreamQueue: downstreamQueue, UpstreamTD: upstreamTD,
			DownstreamTD: downstreamTD}
		gemPorts[instance.EntityID] = gemPort
		graph.GEMPorts = append(graph.GEMPorts, gemPort)
	}

	for _, instance := range snapshot {
		if instance.ClassID != me.GemInterworkingTerminationPointClassID {
			continue
		}
		interworking, err := buildGEMInterworking(instance, instances, gemPorts, bridges, mappers)
		if err != nil {
			return ServiceGraph{}, err
		}
		gemInterworking[instance.EntityID] = interworking
		graph.Interworking = append(graph.Interworking, interworking)
	}

	for _, instance := range snapshot {
		if instance.ClassID != me.MulticastGemInterworkingTerminationPointClassID {
			continue
		}
		interworking, err := buildMulticastGEMInterworking(instance, instances,
			gemPorts, bridges, mappers)
		if err != nil {
			return ServiceGraph{}, err
		}
		multicastInterworking[instance.EntityID] = interworking
		graph.MulticastInterworking = append(graph.MulticastInterworking, interworking)
	}

	for _, mapper := range graph.Mappers {
		if err := validateMapper(mapper, instances, gemInterworking); err != nil {
			return ServiceGraph{}, err
		}
	}

	bridgePortNumbers := make(map[uint16]map[uint8]uint16)
	bridgePorts := make(map[uint16]MACBridgePort)
	for _, instance := range snapshot {
		if instance.ClassID != me.MacBridgePortConfigurationDataClassID {
			continue
		}
		bridgeID, err := uint16Attribute(instance, me.MacBridgePortConfigurationData_BridgeIdPointer)
		if err != nil {
			return ServiceGraph{}, err
		}
		bridge, exists := bridges[bridgeID]
		if !exists {
			return ServiceGraph{}, fmt.Errorf("MAC bridge port %#x references missing bridge profile %#x", instance.EntityID, bridgeID)
		}
		portNumber, err := uint8Attribute(instance, me.MacBridgePortConfigurationData_PortNum)
		if err != nil {
			return ServiceGraph{}, err
		}
		if bridgePortNumbers[bridgeID] == nil {
			bridgePortNumbers[bridgeID] = make(map[uint8]uint16)
		}
		if previous, duplicate := bridgePortNumbers[bridgeID][portNumber]; duplicate {
			return ServiceGraph{}, fmt.Errorf("bridge %#x port number %d is shared by MEs %#x and %#x",
				bridgeID, portNumber, previous, instance.EntityID)
		}
		bridgePortNumbers[bridgeID][portNumber] = instance.EntityID
		tpType, err := uint8Attribute(instance, me.MacBridgePortConfigurationData_TpType)
		if err != nil {
			return ServiceGraph{}, err
		}
		tp, err := uint16Attribute(instance, me.MacBridgePortConfigurationData_TpPointer)
		if err != nil {
			return ServiceGraph{}, err
		}
		if err := validateBridgePortTP(instance.EntityID, bridgeID, tpType, tp, instances,
			gemInterworking, multicastInterworking); err != nil {
			return ServiceGraph{}, err
		}
		port, err := buildMACBridgePort(instance, portNumber, tpType, tp)
		if err != nil {
			return ServiceGraph{}, err
		}
		if err := validateBridgePortTrafficDescriptorPointer(instances, instance.EntityID,
			"outbound", port.OutboundTD); err != nil {
			return ServiceGraph{}, err
		}
		if err := validateBridgePortTrafficDescriptorPointer(instances, instance.EntityID,
			"inbound", port.InboundTD); err != nil {
			return ServiceGraph{}, err
		}
		bridge.Ports = append(bridge.Ports, port)
		bridgePorts[instance.EntityID] = port
	}

	for _, instance := range snapshot {
		if instance.ClassID != me.MulticastSubscriberConfigInfoClassID {
			continue
		}
		subscriber, err := buildMulticastSubscriber(instance, bridgePorts, mappers,
			multicastProfiles)
		if err != nil {
			return ServiceGraph{}, err
		}
		graph.MulticastSubscribers = append(graph.MulticastSubscribers, subscriber)
	}

	associations := make(map[mib.Key]uint16)
	for _, instance := range snapshot {
		switch instance.ClassID {
		case me.VlanTaggingFilterDataClassID:
			filter, err := buildVLANFilter(instance, bridgePorts)
			if err != nil {
				return ServiceGraph{}, err
			}
			graph.VLANFilters = append(graph.VLANFilters, filter)

		case me.VlanTaggingOperationConfigurationDataClassID:
			operation, err := buildVLANOperation(instance, instances)
			if err != nil {
				return ServiceGraph{}, err
			}
			association := mib.Key{ClassID: operation.AssociatedClass, EntityID: operation.AssociatedME}
			if previous, duplicate := associations[association]; duplicate {
				return ServiceGraph{}, fmt.Errorf("VLAN operation MEs %#x and %#x share target %d/%#x",
					previous, operation.EntityID, association.ClassID, association.EntityID)
			}
			associations[association] = operation.EntityID
			graph.VLANOperations = append(graph.VLANOperations, operation)

		case me.ExtendedVlanTaggingOperationConfigurationDataClassID:
			extended, err := buildExtendedVLAN(instance, instances)
			if err != nil {
				return ServiceGraph{}, err
			}
			association := mib.Key{ClassID: extended.AssociatedClass, EntityID: extended.AssociatedME}
			if previous, duplicate := associations[association]; duplicate {
				return ServiceGraph{}, fmt.Errorf("VLAN operation MEs %#x and %#x share target %d/%#x",
					previous, extended.EntityID, association.ClassID, association.EntityID)
			}
			associations[association] = extended.EntityID
			graph.ExtendedVLANs = append(graph.ExtendedVLANs, extended)
		}
	}

	for _, bridge := range bridges {
		sort.Slice(bridge.Ports, func(i, j int) bool { return bridge.Ports[i].Port < bridge.Ports[j].Port })
		graph.Bridges = append(graph.Bridges, *bridge)
	}
	sortServiceGraph(&graph)
	return graph, nil
}

func circuitPackAdministrativeStates(instances map[mib.Key]mib.Instance) (map[uint8]uint8, error) {
	states := make(map[uint8]uint8)
	for _, instance := range instances {
		if instance.ClassID != me.CircuitPackClassID {
			continue
		}
		slot := uint8(instance.EntityID)
		if _, exists := states[slot]; exists {
			return nil, fmt.Errorf("multiple circuit packs declare slot %d", slot)
		}
		state, err := administrativeState(instance, me.CircuitPack_AdministrativeState)
		if err != nil {
			return nil, err
		}
		states[slot] = state
	}
	return states, nil
}

func administrativeState(instance mib.Instance, name string) (uint8, error) {
	state, err := uint8AttributeDefault(instance, name, 0)
	if err != nil {
		return 0, err
	}
	if state > 1 {
		return 0, fmt.Errorf("managed entity %d/%#x has invalid administrative state %d",
			instance.ClassID, instance.EntityID, state)
	}
	return state, nil
}

func buildVLANOperation(instance mib.Instance, instances map[mib.Key]mib.Instance) (VLANOperation, error) {
	upstreamMode, err := uint8Attribute(instance,
		me.VlanTaggingOperationConfigurationData_UpstreamVlanTaggingOperationMode)
	if err != nil {
		return VLANOperation{}, err
	}
	if upstreamMode > 2 {
		return VLANOperation{}, fmt.Errorf("VLAN operation ME %#x has invalid upstream mode %d",
			instance.EntityID, upstreamMode)
	}
	tci, err := uint16Attribute(instance, me.VlanTaggingOperationConfigurationData_UpstreamVlanTagTciValue)
	if err != nil {
		return VLANOperation{}, err
	}
	if upstreamMode != 0 && tci&0x0fff == 0x0fff {
		return VLANOperation{}, fmt.Errorf("VLAN operation ME %#x uses reserved upstream VID 4095",
			instance.EntityID)
	}
	downstreamMode, err := uint8Attribute(instance,
		me.VlanTaggingOperationConfigurationData_DownstreamVlanTaggingOperationMode)
	if err != nil {
		return VLANOperation{}, err
	}
	if downstreamMode > 1 {
		return VLANOperation{}, fmt.Errorf("VLAN operation ME %#x has invalid downstream mode %d",
			instance.EntityID, downstreamMode)
	}
	associationType, err := uint8AttributeDefault(instance,
		me.VlanTaggingOperationConfigurationData_AssociationType, 0)
	if err != nil {
		return VLANOperation{}, err
	}
	pointer := instance.EntityID
	if associationType != 0 {
		pointer, err = uint16Attribute(instance,
			me.VlanTaggingOperationConfigurationData_AssociatedMePointer)
		if err != nil {
			return VLANOperation{}, err
		}
	}
	var targetClass me.ClassID
	switch associationType {
	case 0, 10:
		targetClass = me.PhysicalPathTerminationPointEthernetUniClassID
	case 2:
		targetClass = me.Ieee8021PMapperServiceProfileClassID
	case 3:
		targetClass = me.MacBridgePortConfigurationDataClassID
	case 5:
		targetClass = me.GemInterworkingTerminationPointClassID
	default:
		return VLANOperation{}, fmt.Errorf("VLAN operation ME %#x uses unsupported association type %d",
			instance.EntityID, associationType)
	}
	if !hasInstance(instances, targetClass, pointer) {
		return VLANOperation{}, fmt.Errorf("VLAN operation ME %#x association type %d references missing class %d/%#x",
			instance.EntityID, associationType, targetClass, pointer)
	}
	return VLANOperation{EntityID: instance.EntityID, AssociationType: associationType,
		AssociatedClass: targetClass, AssociatedME: pointer, UpstreamMode: upstreamMode,
		UpstreamTCI: tci, DownstreamMode: downstreamMode}, nil
}

func buildMACBridge(instance mib.Instance) (*MACBridge, error) {
	bridge := &MACBridge{EntityID: instance.EntityID}
	var err error
	bridge.SpanningTree, err = booleanAttributeDefault(instance,
		me.MacBridgeServiceProfile_SpanningTreeInd, 0)
	if err != nil {
		return nil, err
	}
	bridge.Learning, err = booleanAttributeDefault(instance,
		me.MacBridgeServiceProfile_LearningInd, 0)
	if err != nil {
		return nil, err
	}
	bridge.PortBridging, err = booleanAttributeDefault(instance,
		me.MacBridgeServiceProfile_PortBridgingInd, 0)
	if err != nil {
		return nil, err
	}
	bridge.Priority, err = uint16AttributeDefault(instance, me.MacBridgeServiceProfile_Priority, 0)
	if err != nil {
		return nil, err
	}
	bridge.MaxAge, err = uint16AttributeDefault(instance, me.MacBridgeServiceProfile_MaxAge, 0x0600)
	if err != nil {
		return nil, err
	}
	if bridge.MaxAge < 0x0600 || bridge.MaxAge > 0x2800 {
		return nil, fmt.Errorf("MAC bridge %#x max age %#x is outside 6..40 seconds",
			instance.EntityID, bridge.MaxAge)
	}
	bridge.HelloTime, err = uint16AttributeDefault(instance, me.MacBridgeServiceProfile_HelloTime, 0x0100)
	if err != nil {
		return nil, err
	}
	if bridge.HelloTime < 0x0100 || bridge.HelloTime > 0x0a00 {
		return nil, fmt.Errorf("MAC bridge %#x hello time %#x is outside 1..10 seconds",
			instance.EntityID, bridge.HelloTime)
	}
	bridge.ForwardDelay, err = uint16AttributeDefault(instance,
		me.MacBridgeServiceProfile_ForwardDelay, 0x0400)
	if err != nil {
		return nil, err
	}
	if bridge.ForwardDelay < 0x0400 || bridge.ForwardDelay > 0x1e00 {
		return nil, fmt.Errorf("MAC bridge %#x forward delay %#x is outside 4..30 seconds",
			instance.EntityID, bridge.ForwardDelay)
	}
	bridge.UnknownMACDiscard, err = booleanAttributeDefault(instance,
		me.MacBridgeServiceProfile_UnknownMacAddressDiscard, 0)
	if err != nil {
		return nil, err
	}
	bridge.MACLearningDepth, err = uint8AttributeDefault(instance,
		me.MacBridgeServiceProfile_MacLearningDepth, 0)
	if err != nil {
		return nil, err
	}
	bridge.DynamicFilteringAgeTime, err = uint32AttributeDefault(instance,
		me.MacBridgeServiceProfile_DynamicFilteringAgeingTime, 300)
	if err != nil {
		return nil, err
	}
	if bridge.DynamicFilteringAgeTime != 0 &&
		(bridge.DynamicFilteringAgeTime < 10 || bridge.DynamicFilteringAgeTime > 1000000) {
		return nil, fmt.Errorf("MAC bridge %#x dynamic filtering age %d is outside 10..1000000 seconds",
			instance.EntityID, bridge.DynamicFilteringAgeTime)
	}
	return bridge, nil
}

func buildMACBridgePort(instance mib.Instance, portNumber, tpType uint8, tp uint16) (MACBridgePort, error) {
	port := MACBridgePort{EntityID: instance.EntityID, Port: portNumber, TPType: tpType, TP: tp}
	var err error
	port.Priority, err = uint16AttributeDefault(instance, me.MacBridgePortConfigurationData_PortPriority, 0)
	if err != nil {
		return MACBridgePort{}, err
	}
	port.PathCost, err = uint16AttributeDefault(instance, me.MacBridgePortConfigurationData_PortPathCost, 1)
	if err != nil {
		return MACBridgePort{}, err
	}
	if port.PathCost == 0 {
		return MACBridgePort{}, fmt.Errorf("MAC bridge port %#x has zero path cost", instance.EntityID)
	}
	port.SpanningTree, err = booleanAttributeDefault(instance,
		me.MacBridgePortConfigurationData_PortSpanningTreeInd, 0)
	if err != nil {
		return MACBridgePort{}, err
	}
	port.OutboundTD, err = uint16AttributeDefault(instance,
		me.MacBridgePortConfigurationData_OutboundTdPointer, 0)
	if err != nil {
		return MACBridgePort{}, err
	}
	if port.OutboundTD == 0 {
		port.OutboundTD = nullPointer
	}
	port.InboundTD, err = uint16AttributeDefault(instance,
		me.MacBridgePortConfigurationData_InboundTdPointer, 0)
	if err != nil {
		return MACBridgePort{}, err
	}
	if port.InboundTD == 0 {
		port.InboundTD = nullPointer
	}
	port.MACLearningDepth, err = uint8AttributeDefault(instance,
		me.MacBridgePortConfigurationData_MacLearningDepth, 0)
	if err != nil {
		return MACBridgePort{}, err
	}
	return port, nil
}

func booleanAttributeDefault(instance mib.Instance, name string, fallback uint8) (uint8, error) {
	value, err := uint8AttributeDefault(instance, name, fallback)
	if err != nil {
		return 0, err
	}
	if value > 1 {
		return 0, fmt.Errorf("managed entity %d/%#x attribute %s is not boolean: %d",
			instance.ClassID, instance.EntityID, name, value)
	}
	return value, nil
}

func ethernetUNIInterface(entityID uint16) (string, error) {
	switch entityID {
	case 0x0101:
		return "lan1", nil
	case 0x0102:
		return "lan2", nil
	case 0x0103:
		return "lan3", nil
	case 0x0104:
		return "lan4", nil
	default:
		return "", fmt.Errorf("Ethernet UNI %#x has no XG2010G interface mapping", entityID)
	}
}

func buildMapper(instance mib.Instance) (PBitMapper, error) {
	mapper := PBitMapper{EntityID: instance.EntityID}
	var err error
	mapper.TPPointer, err = uint16Attribute(instance, me.Ieee8021PMapperServiceProfile_TpPointer)
	if err != nil {
		return PBitMapper{}, err
	}
	mapper.TPType, err = uint8AttributeDefault(instance, me.Ieee8021PMapperServiceProfile_TpType, 0)
	if err != nil {
		return PBitMapper{}, err
	}
	for priority, name := range mapperPBitAttributes {
		mapper.PBits[priority], err = uint16Attribute(instance, name)
		if err != nil {
			return PBitMapper{}, err
		}
	}
	mapper.UnmarkedFrameOption, err = uint8AttributeDefault(instance,
		me.Ieee8021PMapperServiceProfile_UnmarkedFrameOption, 0)
	if err != nil {
		return PBitMapper{}, err
	}
	if mapper.UnmarkedFrameOption > 1 {
		return PBitMapper{}, fmt.Errorf("802.1p mapper %#x has invalid unmarked frame option %d",
			instance.EntityID, mapper.UnmarkedFrameOption)
	}
	mapper.DefaultPBit, err = uint8AttributeDefault(instance,
		me.Ieee8021PMapperServiceProfile_DefaultPBitAssumption, 0)
	if err != nil {
		return PBitMapper{}, err
	}
	if mapper.DefaultPBit > 7 {
		return PBitMapper{}, fmt.Errorf("802.1p mapper %#x has invalid default P-bit %d",
			instance.EntityID, mapper.DefaultPBit)
	}
	dscpBytes := make([]byte, 24)
	if _, present := instance.Attributes[me.Ieee8021PMapperServiceProfile_DscpToPBitMapping]; present {
		dscpBytes, err = bytesAttribute(instance, me.Ieee8021PMapperServiceProfile_DscpToPBitMapping, 24)
		if err != nil {
			return PBitMapper{}, err
		}
	}
	mapper.DSCPToPBit, err = vlan.DecodeDSCPMapping(dscpBytes)
	if err != nil {
		return PBitMapper{}, err
	}
	return mapper, nil
}

func validateMapper(mapper PBitMapper, instances map[mib.Key]mib.Instance,
	interworking map[uint16]GEMInterworking) error {
	switch mapper.TPType {
	case 0:
		if mapper.TPPointer != nullPointer {
			return fmt.Errorf("802.1p mapper %#x uses bridge mapping but TP pointer is %#x, want 0xffff",
				mapper.EntityID, mapper.TPPointer)
		}
	case 1:
		if !hasInstance(instances, me.PhysicalPathTerminationPointEthernetUniClassID, mapper.TPPointer) {
			return fmt.Errorf("802.1p mapper %#x references missing Ethernet UNI %#x", mapper.EntityID, mapper.TPPointer)
		}
	default:
		return fmt.Errorf("802.1p mapper %#x uses unsupported TP type %d", mapper.EntityID, mapper.TPType)
	}
	for priority, pointer := range mapper.PBits {
		if pointer == nullPointer {
			continue
		}
		iw, exists := interworking[pointer]
		if !exists {
			return fmt.Errorf("802.1p mapper %#x P-bit %d references missing GEM IW TP %#x",
				mapper.EntityID, priority, pointer)
		}
		if iw.Option != 5 || iw.ServiceProfile != mapper.EntityID {
			return fmt.Errorf("802.1p mapper %#x P-bit %d references GEM IW TP %#x owned by option %d/profile %#x",
				mapper.EntityID, priority, pointer, iw.Option, iw.ServiceProfile)
		}
		if mapper.TPType == 0 && iw.InterworkingTermination != 0 && iw.InterworkingTermination != nullPointer {
			return fmt.Errorf("bridging 802.1p mapper %#x P-bit %d GEM IW TP %#x has non-null interworking TP %#x",
				mapper.EntityID, priority, pointer, iw.InterworkingTermination)
		}
		if mapper.TPType == 1 && iw.InterworkingTermination != mapper.TPPointer {
			return fmt.Errorf("direct 802.1p mapper %#x P-bit %d GEM IW TP %#x points to UNI %#x, want %#x",
				mapper.EntityID, priority, pointer, iw.InterworkingTermination, mapper.TPPointer)
		}
	}
	return nil
}

func buildGEMInterworking(instance mib.Instance, instances map[mib.Key]mib.Instance,
	gemPorts map[uint16]GEMPort, bridges map[uint16]*MACBridge,
	mappers map[uint16]PBitMapper) (GEMInterworking, error) {
	pointer, err := uint16Attribute(instance,
		me.GemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer)
	if err != nil {
		return GEMInterworking{}, err
	}
	if _, exists := gemPorts[pointer]; !exists {
		return GEMInterworking{}, fmt.Errorf("GEM IW TP %#x references missing GEM CTP %#x", instance.EntityID, pointer)
	}
	option, err := uint8Attribute(instance, me.GemInterworkingTerminationPoint_InterworkingOption)
	if err != nil {
		return GEMInterworking{}, err
	}
	service, err := uint16Attribute(instance, me.GemInterworkingTerminationPoint_ServiceProfilePointer)
	if err != nil {
		return GEMInterworking{}, err
	}
	switch option {
	case 1:
		if _, exists := bridges[service]; !exists {
			return GEMInterworking{}, fmt.Errorf("GEM IW TP %#x option 1 references missing bridge profile %#x",
				instance.EntityID, service)
		}
	case 5:
		if _, exists := mappers[service]; !exists {
			return GEMInterworking{}, fmt.Errorf("GEM IW TP %#x option 5 references missing 802.1p mapper %#x",
				instance.EntityID, service)
		}
	default:
		return GEMInterworking{}, fmt.Errorf("GEM IW TP %#x uses unsupported interworking option %d", instance.EntityID, option)
	}
	interworkingTP, err := uint16Attribute(instance,
		me.GemInterworkingTerminationPoint_InterworkingTerminationPointPointer)
	if err != nil {
		return GEMInterworking{}, err
	}
	if option == 5 && interworkingTP != 0 && interworkingTP != nullPointer &&
		!hasInstance(instances, me.PhysicalPathTerminationPointEthernetUniClassID, interworkingTP) {
		return GEMInterworking{}, fmt.Errorf("GEM IW TP %#x references missing interworking Ethernet UNI %#x",
			instance.EntityID, interworkingTP)
	}
	gal, err := uint16Attribute(instance, me.GemInterworkingTerminationPoint_GalProfilePointer)
	if err != nil {
		return GEMInterworking{}, err
	}
	if err := validateGALProfile(instances, instance.EntityID, gal); err != nil {
		return GEMInterworking{}, err
	}
	loopback, err := uint8AttributeDefault(instance,
		me.GemInterworkingTerminationPoint_GalLoopbackConfiguration, 0)
	if err != nil {
		return GEMInterworking{}, err
	}
	if loopback != 0 {
		return GEMInterworking{}, fmt.Errorf("GEM IW TP %#x requests unsupported GAL loopback mode %d",
			instance.EntityID, loopback)
	}
	return GEMInterworking{EntityID: instance.EntityID, GEMPort: pointer, Option: option,
		ServiceProfile: service, InterworkingTermination: interworkingTP, GALProfile: gal}, nil
}

func buildMulticastGEMInterworking(instance mib.Instance, instances map[mib.Key]mib.Instance,
	gemPorts map[uint16]GEMPort, bridges map[uint16]*MACBridge,
	mappers map[uint16]PBitMapper) (MulticastGEMInterworking, error) {
	pointer, err := uint16Attribute(instance,
		me.MulticastGemInterworkingTerminationPoint_GemPortNetworkCtpConnectivityPointer)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	gem, exists := gemPorts[pointer]
	if !exists {
		return MulticastGEMInterworking{}, fmt.Errorf("multicast GEM IW TP %#x references missing GEM CTP %#x",
			instance.EntityID, pointer)
	}
	if gem.Direction&1 == 0 {
		return MulticastGEMInterworking{}, fmt.Errorf("multicast GEM IW TP %#x references GEM CTP %#x without downstream direction",
			instance.EntityID, pointer)
	}

	option, err := uint8Attribute(instance,
		me.MulticastGemInterworkingTerminationPoint_InterworkingOption)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	service, err := uint16Attribute(instance,
		me.MulticastGemInterworkingTerminationPoint_ServiceProfilePointer)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	switch option {
	case 0:
	case 1:
		if service != 0 {
			if _, exists := bridges[service]; !exists {
				return MulticastGEMInterworking{}, fmt.Errorf("multicast GEM IW TP %#x option 1 references missing bridge profile %#x",
					instance.EntityID, service)
			}
		}
	case 5:
		if service != 0 {
			if _, exists := mappers[service]; !exists {
				return MulticastGEMInterworking{}, fmt.Errorf("multicast GEM IW TP %#x option 5 references missing 802.1p mapper %#x",
					instance.EntityID, service)
			}
		}
	default:
		return MulticastGEMInterworking{}, fmt.Errorf("multicast GEM IW TP %#x uses unsupported interworking option %d",
			instance.EntityID, option)
	}

	notUsed1, err := uint16AttributeDefault(instance,
		me.MulticastGemInterworkingTerminationPoint_NotUsed1, 0)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	notUsed2, err := uint8AttributeDefault(instance,
		me.MulticastGemInterworkingTerminationPoint_NotUsed2, 0)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	if notUsed1 != 0 || notUsed2 != 0 {
		return MulticastGEMInterworking{}, fmt.Errorf("multicast GEM IW TP %#x has non-zero reserved attributes",
			instance.EntityID)
	}
	gal, err := uint16AttributeDefault(instance,
		me.MulticastGemInterworkingTerminationPoint_GalProfilePointer, 0)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	if gal != 0 {
		if err := validateGALProfile(instances, instance.EntityID, gal); err != nil {
			return MulticastGEMInterworking{}, fmt.Errorf("multicast %w", err)
		}
	}

	ipv4, err := multicastIPv4Ranges(instance)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	ipv6, err := multicastIPv6Ranges(instance)
	if err != nil {
		return MulticastGEMInterworking{}, err
	}
	return MulticastGEMInterworking{
		EntityID: instance.EntityID, GEMPort: pointer, PortID: gem.PortID,
		TCONT: gem.TCONT, AllocID: gem.AllocID, Option: option,
		ServiceProfile: service, GALProfile: gal, IPv4Ranges: ipv4, IPv6Ranges: ipv6,
	}, nil
}

func validateGALProfile(instances map[mib.Key]mib.Instance, interworking, gal uint16) error {
	profile, exists := instances[mib.Key{ClassID: me.GalEthernetProfileClassID, EntityID: gal}]
	if !exists {
		return fmt.Errorf("GEM IW TP %#x references missing GAL Ethernet profile %#x", interworking, gal)
	}
	payload, err := uint16Attribute(profile, me.GalEthernetProfile_MaximumGemPayloadSize)
	if err != nil {
		return err
	}
	if payload != 48 {
		return fmt.Errorf("GAL Ethernet profile %#x has unsupported maximum GEM payload size %d", gal, payload)
	}
	return nil
}

func multicastIPv4Ranges(instance mib.Instance) ([]MulticastIPv4Range, error) {
	rows, err := tableAttributeDefault(instance,
		me.MulticastGemInterworkingTerminationPoint_Ipv4MulticastAddressTable, 12)
	if err != nil {
		return nil, err
	}
	ranges := make([]MulticastIPv4Range, 0, rows.NumRows)
	keys := make(map[uint32]struct{}, rows.NumRows)
	for offset := 0; offset < len(rows.Rows); offset += 12 {
		row := rows.Rows[offset : offset+12]
		portID := binary.BigEndian.Uint16(row[0:2])
		secondary := binary.BigEndian.Uint16(row[2:4])
		start := binary.BigEndian.Uint32(row[4:8])
		stop := binary.BigEndian.Uint32(row[8:12])
		if portID > 0x0fff || start>>28 != 0xe || stop>>28 != 0xe || start > stop {
			return nil, fmt.Errorf("multicast GEM IW TP %#x has invalid IPv4 address row %x",
				instance.EntityID, row)
		}
		key := uint32(portID)<<16 | uint32(secondary)
		if _, duplicate := keys[key]; duplicate {
			return nil, fmt.Errorf("multicast GEM IW TP %#x repeats IPv4 address row key %d/%d",
				instance.EntityID, portID, secondary)
		}
		keys[key] = struct{}{}
		var startBytes, stopBytes [4]byte
		binary.BigEndian.PutUint32(startBytes[:], start)
		binary.BigEndian.PutUint32(stopBytes[:], stop)
		ranges = append(ranges, MulticastIPv4Range{
			GEMPortID: portID, SecondaryKey: secondary,
			Start: netip.AddrFrom4(startBytes).String(), Stop: netip.AddrFrom4(stopBytes).String(),
		})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].GEMPortID != ranges[j].GEMPortID {
			return ranges[i].GEMPortID < ranges[j].GEMPortID
		}
		return ranges[i].SecondaryKey < ranges[j].SecondaryKey
	})
	return ranges, nil
}

func multicastIPv6Ranges(instance mib.Instance) ([]MulticastIPv6Range, error) {
	rows, err := tableAttributeDefault(instance,
		me.MulticastGemInterworkingTerminationPoint_Ipv6MulticastAddressTable, 24)
	if err != nil {
		return nil, err
	}
	ranges := make([]MulticastIPv6Range, 0, rows.NumRows)
	keys := make(map[uint32]struct{}, rows.NumRows)
	for offset := 0; offset < len(rows.Rows); offset += 24 {
		row := rows.Rows[offset : offset+24]
		portID := binary.BigEndian.Uint16(row[0:2])
		secondary := binary.BigEndian.Uint16(row[2:4])
		startLow := binary.BigEndian.Uint32(row[4:8])
		stopLow := binary.BigEndian.Uint32(row[8:12])
		if portID > 0x0fff || row[12] != 0xff || startLow > stopLow {
			return nil, fmt.Errorf("multicast GEM IW TP %#x has invalid IPv6 address row %x",
				instance.EntityID, row)
		}
		key := uint32(portID)<<16 | uint32(secondary)
		if _, duplicate := keys[key]; duplicate {
			return nil, fmt.Errorf("multicast GEM IW TP %#x repeats IPv6 address row key %d/%d",
				instance.EntityID, portID, secondary)
		}
		keys[key] = struct{}{}
		var start, stop [16]byte
		copy(start[:12], row[12:24])
		copy(stop[:12], row[12:24])
		copy(start[12:], row[4:8])
		copy(stop[12:], row[8:12])
		ranges = append(ranges, MulticastIPv6Range{
			GEMPortID: portID, SecondaryKey: secondary,
			Start: netip.AddrFrom16(start).String(), Stop: netip.AddrFrom16(stop).String(),
		})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].GEMPortID != ranges[j].GEMPortID {
			return ranges[i].GEMPortID < ranges[j].GEMPortID
		}
		return ranges[i].SecondaryKey < ranges[j].SecondaryKey
	})
	return ranges, nil
}

func buildMulticastOperationsProfile(instance mib.Instance) (MulticastOperationsProfile, error) {
	profile := MulticastOperationsProfile{EntityID: instance.EntityID}
	var err error
	if profile.IGMPVersion, err = uint8Attribute(instance,
		me.MulticastOperationsProfile_IgmpVersion); err != nil {
		return MulticastOperationsProfile{}, err
	}
	switch profile.IGMPVersion {
	case 1, 2, 3, 16, 17:
	default:
		return MulticastOperationsProfile{}, fmt.Errorf("multicast operations profile %#x uses invalid IGMP/MLD version %d",
			instance.EntityID, profile.IGMPVersion)
	}
	if profile.IGMPFunction, err = uint8Attribute(instance,
		me.MulticastOperationsProfile_IgmpFunction); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.IGMPFunction > 2 {
		return MulticastOperationsProfile{}, fmt.Errorf("multicast operations profile %#x uses invalid IGMP function %d",
			instance.EntityID, profile.IGMPFunction)
	}
	if profile.ImmediateLeave, err = booleanAttributeDefault(instance,
		me.MulticastOperationsProfile_ImmediateLeave, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.UpstreamTCI, err = uint16AttributeDefault(instance,
		me.MulticastOperationsProfile_UpstreamIgmpTci, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.UpstreamTagControl, err = uint8AttributeDefault(instance,
		me.MulticastOperationsProfile_UpstreamIgmpTagControl, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.UpstreamTagControl > 3 ||
		(profile.UpstreamTagControl != 0 && profile.UpstreamTCI&0x0fff == 0x0fff) {
		return MulticastOperationsProfile{}, fmt.Errorf("multicast operations profile %#x has invalid upstream tag control/TCI %d/%#x",
			instance.EntityID, profile.UpstreamTagControl, profile.UpstreamTCI)
	}
	if profile.UpstreamRate, err = uint32AttributeDefault(instance,
		me.MulticastOperationsProfile_UpstreamIgmpRate, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}

	if profile.DynamicACL, err = multicastACL(instance,
		me.MulticastOperationsProfile_DynamicAccessControlListTable); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.StaticACL, err = multicastACL(instance,
		me.MulticastOperationsProfile_StaticAccessControlListTable); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.Robustness, err = uint8AttributeDefault(instance,
		me.MulticastOperationsProfile_Robustness, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.QuerierIPAddress, err = uint32AttributeDefault(instance,
		me.MulticastOperationsProfile_QuerierIpAddress, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.QueryInterval, err = uint32AttributeDefault(instance,
		me.MulticastOperationsProfile_QueryInterval, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.QueryMaxResponseTime, err = uint32AttributeDefault(instance,
		me.MulticastOperationsProfile_QueryMaxResponseTime, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.LastMemberQueryInterval, err = uint32AttributeDefault(instance,
		me.MulticastOperationsProfile_LastMemberQueryInterval, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.UnauthorizedJoinBehaviour, err = uint8AttributeDefault(instance,
		me.MulticastOperationsProfile_UnauthorizedJoinRequestBehaviour, 0); err != nil {
		return MulticastOperationsProfile{}, err
	}
	if profile.UnauthorizedJoinBehaviour > 1 {
		return MulticastOperationsProfile{}, fmt.Errorf("multicast operations profile %#x has invalid unauthorized-join behaviour %d",
			instance.EntityID, profile.UnauthorizedJoinBehaviour)
	}
	downstream, err := bytesAttributeDefault(instance,
		me.MulticastOperationsProfile_DownstreamIgmpAndMulticastTci, 3, []byte{0, 0, 0})
	if err != nil {
		return MulticastOperationsProfile{}, err
	}
	profile.DownstreamTagControl = downstream[0]
	profile.DownstreamTCI = binary.BigEndian.Uint16(downstream[1:3])
	if profile.DownstreamTagControl > 7 ||
		(profile.DownstreamTagControl >= 2 && profile.DownstreamTCI&0x0fff == 0x0fff) {
		return MulticastOperationsProfile{}, fmt.Errorf("multicast operations profile %#x has invalid downstream tag control/TCI %d/%#x",
			instance.EntityID, profile.DownstreamTagControl, profile.DownstreamTCI)
	}
	return profile, nil
}

func multicastACL(instance mib.Instance, name string) ([]MulticastACLEntry, error) {
	const rowSize = 24
	rows, err := tableAttributeDefault(instance, name, rowSize)
	if err != nil {
		return nil, err
	}
	type parts [3][]byte
	logical := make(map[uint16]parts)
	for offset := 0; offset < len(rows.Rows); offset += rowSize {
		row := rows.Rows[offset : offset+rowSize]
		control := binary.BigEndian.Uint16(row[:2])
		part := uint8((control >> 11) & 0x07)
		key := control & 0x03ff
		if control&0xc400 != 0 || part > 2 {
			return nil, fmt.Errorf("multicast operations profile %#x %s row has invalid stored control %#x",
				instance.EntityID, name, control)
		}
		entry := logical[key]
		if entry[part] != nil {
			return nil, fmt.Errorf("multicast operations profile %#x %s repeats row key/part %d/%d",
				instance.EntityID, name, key, part)
		}
		entry[part] = append([]byte(nil), row...)
		logical[key] = entry
	}

	keys := make([]int, 0, len(logical))
	for key := range logical {
		keys = append(keys, int(key))
	}
	sort.Ints(keys)
	result := make([]MulticastACLEntry, 0, len(keys))
	for _, keyValue := range keys {
		key := uint16(keyValue)
		entry := logical[key]
		if entry[0] == nil {
			// A multi-part table is updated one part at a time. Extension parts
			// have no forwarding meaning until row part 0 is present.
			continue
		}
		resolved, err := resolveMulticastACLEntry(instance, name, key, entry)
		if err != nil {
			return nil, err
		}
		for _, previous := range result {
			if previous.IPVersion != resolved.IPVersion {
				continue
			}
			previousStart := netip.MustParseAddr(previous.Start)
			previousStop := netip.MustParseAddr(previous.Stop)
			start := netip.MustParseAddr(resolved.Start)
			stop := netip.MustParseAddr(resolved.Stop)
			if previousStop.Compare(start) < 0 || stop.Compare(previousStart) < 0 {
				continue
			}
			return nil, fmt.Errorf("multicast operations profile %#x %s row key %d overlaps row key %d",
				instance.EntityID, name, key, previous.RowKey)
		}
		result = append(result, resolved)
	}
	return result, nil
}

func resolveMulticastACLEntry(instance mib.Instance, name string, key uint16,
	parts [3][]byte) (MulticastACLEntry, error) {
	part0 := parts[0]
	result := MulticastACLEntry{
		RowKey:           key,
		GEMPortID:        binary.BigEndian.Uint16(part0[2:4]),
		VLANID:           binary.BigEndian.Uint16(part0[4:6]),
		ImputedBandwidth: binary.BigEndian.Uint32(part0[18:22]),
	}
	if result.GEMPortID > 0x0fff {
		return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has invalid GEM Port-ID %d",
			instance.EntityID, name, key, result.GEMPortID)
	}
	if result.VLANID == 4096 || result.VLANID > 4097 && result.VLANID != 0xffff {
		return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has invalid VLAN ID %d",
			instance.EntityID, name, key, result.VLANID)
	}
	if !zeroBytes(part0[22:24]) {
		return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has non-zero part 0 reserved bytes",
			instance.EntityID, name, key)
	}

	source, _ := multicastACLAddress(parts[1], part0[6:10])
	start, destinationIPv6 := multicastACLAddress(parts[2], part0[10:14])
	stop, stopIPv6 := multicastACLAddress(parts[2], part0[14:18])
	if destinationIPv6 != stopIPv6 || start.Compare(stop) > 0 ||
		(!destinationIPv6 && !start.Is4() || !destinationIPv6 && !stop.Is4()) ||
		(destinationIPv6 && !start.Is6() || destinationIPv6 && !stop.Is6()) ||
		!start.IsMulticast() || !stop.IsMulticast() {
		return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has invalid destination range %s..%s",
			instance.EntityID, name, key, start, stop)
	}
	result.IPVersion = 4
	if destinationIPv6 {
		result.IPVersion = 6
	}
	result.Source = source.String()
	result.Start = start.String()
	result.Stop = stop.String()

	if part1 := parts[1]; part1 != nil {
		if !zeroBytes(part1[22:24]) {
			return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has non-zero part 1 reserved bytes",
				instance.EntityID, name, key)
		}
		result.PreviewLength = binary.BigEndian.Uint16(part1[14:16])
		result.PreviewRepeatTime = binary.BigEndian.Uint16(part1[16:18])
		result.PreviewRepeatCount = binary.BigEndian.Uint16(part1[18:20])
		result.PreviewResetTime = binary.BigEndian.Uint16(part1[20:22])
		if name == me.MulticastOperationsProfile_DynamicAccessControlListTable &&
			result.PreviewResetTime > 24 && result.PreviewResetTime < 241 {
			return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has reserved preview reset time %d",
				instance.EntityID, name, key, result.PreviewResetTime)
		}
	}
	if part2 := parts[2]; part2 != nil && !zeroBytes(part2[14:24]) {
		return MulticastACLEntry{}, fmt.Errorf("multicast operations profile %#x %s row key %d has non-zero part 2 reserved bytes",
			instance.EntityID, name, key)
	}
	return result, nil
}

func multicastACLAddress(prefixPart, low []byte) (netip.Addr, bool) {
	if prefixPart == nil || ipv4AddressPrefix(prefixPart[2:14]) {
		var value [4]byte
		copy(value[:], low)
		return netip.AddrFrom4(value), false
	}
	var value [16]byte
	copy(value[:12], prefixPart[2:14])
	copy(value[12:], low)
	return netip.AddrFrom16(value), true
}

func ipv4AddressPrefix(prefix []byte) bool {
	return zeroBytes(prefix[:10]) &&
		((prefix[10] == 0 && prefix[11] == 0) || (prefix[10] == 0xff && prefix[11] == 0xff))
}

func zeroBytes(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func buildMulticastSubscriber(instance mib.Instance, bridgePorts map[uint16]MACBridgePort,
	mappers map[uint16]PBitMapper, profiles map[uint16]MulticastOperationsProfile) (MulticastSubscriberConfigInfo, error) {
	subscriber := MulticastSubscriberConfigInfo{EntityID: instance.EntityID}
	var err error
	if subscriber.METype, err = uint8Attribute(instance,
		me.MulticastSubscriberConfigInfo_MeType); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	switch subscriber.METype {
	case 0:
		port, exists := bridgePorts[instance.EntityID]
		if !exists || port.TPType != 1 {
			return MulticastSubscriberConfigInfo{}, fmt.Errorf("multicast subscriber %#x does not identify an Ethernet UNI bridge port",
				instance.EntityID)
		}
	case 1:
		if _, exists := mappers[instance.EntityID]; !exists {
			return MulticastSubscriberConfigInfo{}, fmt.Errorf("multicast subscriber %#x references missing 802.1p mapper",
				instance.EntityID)
		}
	default:
		return MulticastSubscriberConfigInfo{}, fmt.Errorf("multicast subscriber %#x uses invalid ME type %d",
			instance.EntityID, subscriber.METype)
	}
	if subscriber.Profile, err = uint16Attribute(instance,
		me.MulticastSubscriberConfigInfo_MulticastOperationsProfilePointer); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	if subscriber.MaxSimultaneousGroups, err = uint16AttributeDefault(instance,
		me.MulticastSubscriberConfigInfo_MaxSimultaneousGroups, 0); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	if subscriber.MaxMulticastBandwidth, err = uint32AttributeDefault(instance,
		me.MulticastSubscriberConfigInfo_MaxMulticastBandwidth, 0); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	if subscriber.BandwidthEnforcement, err = booleanAttributeDefault(instance,
		me.MulticastSubscriberConfigInfo_BandwidthEnforcement, 0); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	if subscriber.ServicePackages, err = multicastServicePackages(instance, profiles); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	if len(subscriber.ServicePackages) == 0 {
		if _, exists := profiles[subscriber.Profile]; !exists {
			return MulticastSubscriberConfigInfo{}, fmt.Errorf("multicast subscriber %#x references missing operations profile %#x",
				instance.EntityID, subscriber.Profile)
		}
	}
	if subscriber.AllowedPreviewGroups, err = allowedPreviewGroups(instance); err != nil {
		return MulticastSubscriberConfigInfo{}, err
	}
	return subscriber, nil
}

func multicastServicePackages(instance mib.Instance,
	profiles map[uint16]MulticastOperationsProfile) ([]MulticastServicePackage, error) {
	const rowSize = 20
	rows, err := tableAttributeDefault(instance,
		me.MulticastSubscriberConfigInfo_MulticastServicePackageTable, rowSize)
	if err != nil {
		return nil, err
	}
	result := make([]MulticastServicePackage, 0, rows.NumRows)
	seen := make(map[uint16]struct{}, rows.NumRows)
	for offset := 0; offset < len(rows.Rows); offset += rowSize {
		row := rows.Rows[offset : offset+rowSize]
		control := binary.BigEndian.Uint16(row[:2])
		key := control & 0x03ff
		if control&0xfc00 != 0 {
			return nil, fmt.Errorf("multicast subscriber %#x service package has invalid stored control %#x",
				instance.EntityID, control)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("multicast subscriber %#x repeats service package row key %d",
				instance.EntityID, key)
		}
		seen[key] = struct{}{}
		entry := MulticastServicePackage{
			RowKey:                key,
			VLANID:                binary.BigEndian.Uint16(row[2:4]),
			MaxSimultaneousGroups: binary.BigEndian.Uint16(row[4:6]),
			MaxMulticastBandwidth: binary.BigEndian.Uint32(row[6:10]),
			OperationsProfile:     binary.BigEndian.Uint16(row[10:12]),
		}
		if entry.VLANID > 4097 && entry.VLANID != 0xffff {
			return nil, fmt.Errorf("multicast subscriber %#x service package row key %d has invalid VLAN ID %d",
				instance.EntityID, key, entry.VLANID)
		}
		if _, exists := profiles[entry.OperationsProfile]; !exists {
			return nil, fmt.Errorf("multicast subscriber %#x service package row key %d references missing operations profile %#x",
				instance.EntityID, key, entry.OperationsProfile)
		}
		if !zeroBytes(row[12:20]) {
			return nil, fmt.Errorf("multicast subscriber %#x service package row key %d has non-zero reserved bytes",
				instance.EntityID, key)
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RowKey < result[j].RowKey })
	return result, nil
}

func allowedPreviewGroups(instance mib.Instance) ([]AllowedPreviewGroup, error) {
	const rowSize = 22
	rows, err := tableAttributeDefault(instance,
		me.MulticastSubscriberConfigInfo_AllowedPreviewGroupsTable, rowSize)
	if err != nil {
		return nil, err
	}
	type parts [2][]byte
	logical := make(map[uint16]parts)
	for offset := 0; offset < len(rows.Rows); offset += rowSize {
		row := rows.Rows[offset : offset+rowSize]
		control := binary.BigEndian.Uint16(row[:2])
		part := uint8((control >> 11) & 0x07)
		key := control & 0x03ff
		if control&0xc400 != 0 || part > 1 {
			return nil, fmt.Errorf("multicast subscriber %#x preview row has invalid stored control %#x",
				instance.EntityID, control)
		}
		entry := logical[key]
		if entry[part] != nil {
			return nil, fmt.Errorf("multicast subscriber %#x repeats preview row key/part %d/%d",
				instance.EntityID, key, part)
		}
		entry[part] = append([]byte(nil), row...)
		logical[key] = entry
	}
	keys := make([]int, 0, len(logical))
	for key := range logical {
		keys = append(keys, int(key))
	}
	sort.Ints(keys)
	result := make([]AllowedPreviewGroup, 0, len(keys))
	for _, keyValue := range keys {
		key := uint16(keyValue)
		parts := logical[key]
		if parts[0] == nil || parts[1] == nil {
			continue
		}
		source, _ := multicastTableAddress(parts[0][2:18])
		destination, ipv6 := multicastTableAddress(parts[1][2:18])
		aniVLAN := binary.BigEndian.Uint16(parts[0][18:20])
		uniVLAN := binary.BigEndian.Uint16(parts[0][20:22])
		if aniVLAN > 4095 || uniVLAN > 4095 || !destination.IsMulticast() {
			return nil, fmt.Errorf("multicast subscriber %#x preview row key %d has invalid VLAN/address",
				instance.EntityID, key)
		}
		ipVersion := uint8(4)
		if ipv6 {
			ipVersion = 6
		}
		result = append(result, AllowedPreviewGroup{
			RowKey: key, IPVersion: ipVersion, Source: source.String(), Destination: destination.String(),
			ANIVLAN: aniVLAN, UNIVLAN: uniVLAN,
			Duration: binary.BigEndian.Uint16(parts[1][18:20]),
			TimeLeft: binary.BigEndian.Uint16(parts[1][20:22]),
		})
	}
	return result, nil
}

func multicastTableAddress(value []byte) (netip.Addr, bool) {
	if zeroBytes(value[:12]) {
		var ipv4 [4]byte
		copy(ipv4[:], value[12:16])
		return netip.AddrFrom4(ipv4), false
	}
	var ipv6 [16]byte
	copy(ipv6[:], value)
	return netip.AddrFrom16(ipv6), true
}

func validateBridgePortTP(entityID, bridgeID uint16, tpType uint8, pointer uint16,
	instances map[mib.Key]mib.Instance, interworking map[uint16]GEMInterworking,
	multicast map[uint16]MulticastGEMInterworking) error {
	var classID me.ClassID
	switch tpType {
	case 1:
		classID = me.PhysicalPathTerminationPointEthernetUniClassID
	case 3:
		classID = me.Ieee8021PMapperServiceProfileClassID
	case 5:
		classID = me.GemInterworkingTerminationPointClassID
	case 6:
		classID = me.MulticastGemInterworkingTerminationPointClassID
	default:
		return fmt.Errorf("MAC bridge port %#x uses unsupported TP type %d", entityID, tpType)
	}
	if !hasInstance(instances, classID, pointer) {
		return fmt.Errorf("MAC bridge port %#x TP type %d references missing class %d/%#x",
			entityID, tpType, classID, pointer)
	}
	if tpType == 5 {
		iw := interworking[pointer]
		if iw.Option != 1 || iw.ServiceProfile != bridgeID {
			return fmt.Errorf("MAC bridge port %#x references GEM IW TP %#x option/profile %d/%#x, want 1/%#x",
				entityID, pointer, iw.Option, iw.ServiceProfile, bridgeID)
		}
	} else if tpType == 6 {
		iw := multicast[pointer]
		if iw.Option == 1 && iw.ServiceProfile != 0 && iw.ServiceProfile != bridgeID {
			return fmt.Errorf("MAC bridge port %#x references multicast GEM IW TP %#x bridge profile %#x, want %#x",
				entityID, pointer, iw.ServiceProfile, bridgeID)
		}
	} else if tpType == 3 {
		mapper := instances[mib.Key{ClassID: me.Ieee8021PMapperServiceProfileClassID, EntityID: pointer}]
		mapperTPType, err := uint8AttributeDefault(mapper, me.Ieee8021PMapperServiceProfile_TpType, 0)
		if err != nil {
			return err
		}
		if mapperTPType != 0 {
			return fmt.Errorf("MAC bridge port %#x references non-bridging 802.1p mapper %#x TP type %d",
				entityID, pointer, mapperTPType)
		}
	}
	return nil
}

func buildVLANFilter(instance mib.Instance, bridgePorts map[uint16]MACBridgePort) (VLANFilter, error) {
	if _, exists := bridgePorts[instance.EntityID]; !exists {
		return VLANFilter{}, fmt.Errorf("VLAN filter %#x has no implicitly linked MAC bridge port", instance.EntityID)
	}
	list, err := bytesAttribute(instance, me.VlanTaggingFilterData_VlanFilterList, 24)
	if err != nil {
		return VLANFilter{}, err
	}
	count, err := uint8Attribute(instance, me.VlanTaggingFilterData_NumberOfEntries)
	if err != nil {
		return VLANFilter{}, err
	}
	if count > 12 {
		return VLANFilter{}, fmt.Errorf("VLAN filter %#x has %d entries, maximum is 12", instance.EntityID, count)
	}
	entries := make([]uint16, count)
	for index := range entries {
		entries[index] = uint16(list[index*2])<<8 | uint16(list[index*2+1])
		if entries[index]&0x0fff == 0x0fff {
			return VLANFilter{}, fmt.Errorf("VLAN filter %#x entry %d uses reserved VID 4095", instance.EntityID, index)
		}
	}
	operation, err := uint8Attribute(instance, me.VlanTaggingFilterData_ForwardOperation)
	if err != nil {
		return VLANFilter{}, err
	}
	taggedAction, criterion, untaggedAction, err := decodeVLANForwardOperation(operation)
	if err != nil {
		return VLANFilter{}, fmt.Errorf("VLAN filter %#x: %w", instance.EntityID, err)
	}
	return VLANFilter{EntityID: instance.EntityID, BridgePort: instance.EntityID,
		ForwardOperation: operation, TaggedAction: taggedAction, TaggedCriterion: criterion,
		UntaggedAction: untaggedAction, Entries: entries}, nil
}

func decodeVLANForwardOperation(operation uint8) (VLANFilterAction, VLANFilterCriterion,
	VLANFilterAction, error) {
	untagged := VLANFilterActionBridge
	if operation == 0x02 || operation == 0x04 || operation == 0x06 || operation == 0x08 ||
		operation == 0x0a || operation == 0x0c || operation == 0x0e || operation == 0x10 ||
		operation == 0x12 || operation == 0x14 || operation == 0x15 || operation == 0x17 ||
		operation == 0x19 || operation == 0x1b || operation == 0x1d || operation == 0x1f ||
		operation == 0x21 {
		untagged = VLANFilterActionDiscard
	}

	switch operation {
	case 0x00, 0x02, 0x15:
		return VLANFilterActionBridge, VLANFilterCriterionNone, untagged, nil
	case 0x01:
		return VLANFilterActionDiscard, VLANFilterCriterionNone, untagged, nil
	case 0x03, 0x04, 0x0f, 0x10, 0x1c, 0x1d:
		return VLANFilterActionPositive, VLANFilterCriterionVID, untagged, nil
	case 0x05, 0x06:
		return VLANFilterActionNegative, VLANFilterCriterionVID, untagged, nil
	case 0x07, 0x08, 0x11, 0x12, 0x1e, 0x1f:
		return VLANFilterActionPositive, VLANFilterCriterionPriority, untagged, nil
	case 0x09, 0x0a:
		return VLANFilterActionNegative, VLANFilterCriterionPriority, untagged, nil
	case 0x0b, 0x0c, 0x13, 0x14, 0x20, 0x21:
		return VLANFilterActionPositive, VLANFilterCriterionTCI, untagged, nil
	case 0x0d, 0x0e:
		return VLANFilterActionNegative, VLANFilterCriterionTCI, untagged, nil
	case 0x16, 0x17:
		return VLANFilterActionPositiveDA, VLANFilterCriterionVID, untagged, nil
	case 0x18, 0x19:
		return VLANFilterActionPositiveDA, VLANFilterCriterionPriority, untagged, nil
	case 0x1a, 0x1b:
		return VLANFilterActionPositiveDA, VLANFilterCriterionTCI, untagged, nil
	default:
		return "", "", "", fmt.Errorf("forward operation %#02x is reserved", operation)
	}
}

func buildExtendedVLAN(instance mib.Instance, instances map[mib.Key]mib.Instance) (ExtendedVLAN, error) {
	associationType, err := uint8Attribute(instance,
		me.ExtendedVlanTaggingOperationConfigurationData_AssociationType)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	pointer, err := uint16Attribute(instance,
		me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	var targetClass me.ClassID
	switch associationType {
	case 0:
		targetClass = me.MacBridgePortConfigurationDataClassID
	case 1:
		targetClass = me.Ieee8021PMapperServiceProfileClassID
	case 2:
		targetClass = me.PhysicalPathTerminationPointEthernetUniClassID
	case 5:
		targetClass = me.GemInterworkingTerminationPointClassID
	default:
		return ExtendedVLAN{}, fmt.Errorf("extended VLAN ME %#x uses unsupported association type %d",
			instance.EntityID, associationType)
	}
	if !hasInstance(instances, targetClass, pointer) {
		return ExtendedVLAN{}, fmt.Errorf("extended VLAN ME %#x association type %d references missing class %d/%#x",
			instance.EntityID, associationType, targetClass, pointer)
	}
	inputTPID, err := uint16Attribute(instance, me.ExtendedVlanTaggingOperationConfigurationData_InputTpid)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	outputTPID, err := uint16Attribute(instance, me.ExtendedVlanTaggingOperationConfigurationData_OutputTpid)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	downstream, err := uint8Attribute(instance, me.ExtendedVlanTaggingOperationConfigurationData_DownstreamMode)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	if downstream > 8 {
		return ExtendedVLAN{}, fmt.Errorf("extended VLAN ME %#x has invalid downstream mode %d", instance.EntityID, downstream)
	}
	enhanced, err := uint8AttributeDefault(instance, me.ExtendedVlanTaggingOperationConfigurationData_EnhancedMode, 0)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	if enhanced > 1 {
		return ExtendedVLAN{}, fmt.Errorf("extended VLAN ME %#x has invalid enhanced mode %d", instance.EntityID, enhanced)
	}
	name := me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable
	rowSize := vlan.ClassicRowSize
	if enhanced == 1 {
		name = me.ExtendedVlanTaggingOperationConfigurationData_EnhancedReceivedFrameClassificationAndProcessingTable
		rowSize = vlan.EnhancedRowSize
	}
	rules, err := tableAttributeDefault(instance, name, rowSize)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	maximum, err := uint16AttributeDefault(instance,
		me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize, 0)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	if maximum != 0 && rules.NumRows > int(maximum) {
		return ExtendedVLAN{}, fmt.Errorf("extended VLAN ME %#x has %d rules, maximum is %d",
			instance.EntityID, rules.NumRows, maximum)
	}
	parsedRules, err := vlan.ParseRows(rules.Rows, enhanced == 1)
	if err != nil {
		return ExtendedVLAN{}, fmt.Errorf("extended VLAN ME %#x: %w", instance.EntityID, err)
	}
	dscpBytes := make([]byte, 24)
	if _, present := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_DscpToPBitMapping]; present {
		dscpBytes, err = bytesAttribute(instance,
			me.ExtendedVlanTaggingOperationConfigurationData_DscpToPBitMapping, 24)
		if err != nil {
			return ExtendedVLAN{}, err
		}
	}
	dscpMapping, err := vlan.DecodeDSCPMapping(dscpBytes)
	if err != nil {
		return ExtendedVLAN{}, err
	}
	return ExtendedVLAN{EntityID: instance.EntityID, AssociationType: associationType,
		AssociatedClass: targetClass, AssociatedME: pointer, InputTPID: inputTPID, OutputTPID: outputTPID,
		DownstreamMode: downstream, EnhancedMode: enhanced, DSCPToPBit: dscpMapping,
		Rules: parsedRules}, nil
}

func validateUpstreamTrafficPointer(instances map[mib.Key]mib.Instance, gem, tcont,
	pointer uint16, option uint8) error {
	if option == 1 {
		if pointer != tcont {
			return fmt.Errorf("GEM CTP %#x rate-controlled upstream pointer %#x does not match T-CONT %#x",
				gem, pointer, tcont)
		}
		return nil
	}
	queue, exists := instances[mib.Key{ClassID: me.PriorityQueueClassID, EntityID: pointer}]
	if !exists {
		return fmt.Errorf("GEM CTP %#x references missing upstream priority queue %#x", gem, pointer)
	}
	related, err := uint32Attribute(queue, me.PriorityQueue_RelatedPort)
	if err != nil {
		return err
	}
	if uint16(related>>16) != tcont {
		return fmt.Errorf("GEM CTP %#x upstream queue %#x belongs to %#x, not T-CONT %#x",
			gem, pointer, uint16(related>>16), tcont)
	}
	return nil
}

func validateTrafficDescriptorPointer(instances map[mib.Key]mib.Instance, gem uint16,
	direction string, pointer uint16) error {
	if pointer == nullPointer {
		return nil
	}
	if !hasInstance(instances, me.TrafficDescriptorClassID, pointer) {
		return fmt.Errorf("GEM CTP %#x references missing %s traffic descriptor %#x",
			gem, direction, pointer)
	}
	return nil
}

func validateBridgePortTrafficDescriptorPointer(instances map[mib.Key]mib.Instance,
	port uint16, direction string, pointer uint16) error {
	if pointer == nullPointer {
		return nil
	}
	if !hasInstance(instances, me.TrafficDescriptorClassID, pointer) {
		return fmt.Errorf("MAC bridge port %#x references missing %s traffic descriptor %#x",
			port, direction, pointer)
	}
	return nil
}

func buildTrafficDescriptor(instance mib.Instance) (TrafficDescriptor, error) {
	descriptor := TrafficDescriptor{EntityID: instance.EntityID}
	var err error
	if descriptor.CIR, err = uint32AttributeDefault(instance, me.TrafficDescriptor_Cir, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.PIR, err = uint32AttributeDefault(instance, me.TrafficDescriptor_Pir, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.CBS, err = uint32AttributeDefault(instance, me.TrafficDescriptor_Cbs, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.PBS, err = uint32AttributeDefault(instance, me.TrafficDescriptor_Pbs, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.ColourMode, err = uint8AttributeDefault(instance, me.TrafficDescriptor_ColourMode, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.IngressColourMarking, err = uint8AttributeDefault(instance,
		me.TrafficDescriptor_IngressColourMarking, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.EgressColourMarking, err = uint8AttributeDefault(instance,
		me.TrafficDescriptor_EgressColourMarking, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.MeterType, err = uint8AttributeDefault(instance, me.TrafficDescriptor_MeterType, 0); err != nil {
		return TrafficDescriptor{}, err
	}
	if descriptor.PIR != 0 && descriptor.CIR > descriptor.PIR {
		return TrafficDescriptor{}, fmt.Errorf("traffic descriptor %#x has CIR %d above PIR %d",
			descriptor.EntityID, descriptor.CIR, descriptor.PIR)
	}
	if descriptor.ColourMode > 1 {
		return TrafficDescriptor{}, fmt.Errorf("traffic descriptor %#x has invalid colour mode %d",
			descriptor.EntityID, descriptor.ColourMode)
	}
	if descriptor.IngressColourMarking == 1 || descriptor.IngressColourMarking > 7 {
		return TrafficDescriptor{}, fmt.Errorf("traffic descriptor %#x has invalid ingress colour marking %d",
			descriptor.EntityID, descriptor.IngressColourMarking)
	}
	if descriptor.EgressColourMarking > 7 {
		return TrafficDescriptor{}, fmt.Errorf("traffic descriptor %#x has invalid egress colour marking %d",
			descriptor.EntityID, descriptor.EgressColourMarking)
	}
	if descriptor.MeterType > 2 {
		return TrafficDescriptor{}, fmt.Errorf("traffic descriptor %#x has invalid meter type %d",
			descriptor.EntityID, descriptor.MeterType)
	}
	return descriptor, nil
}

func buildDot1RateLimiter(instance mib.Instance,
	instances map[mib.Key]mib.Instance) (Dot1RateLimiter, mib.Key, error) {
	limiter := Dot1RateLimiter{EntityID: instance.EntityID}
	var err error
	if limiter.ParentME, err = uint16Attribute(instance,
		me.Dot1RateLimiter_ParentMePointer); err != nil {
		return Dot1RateLimiter{}, mib.Key{}, err
	}
	if limiter.TPType, err = uint8Attribute(instance, me.Dot1RateLimiter_TpType); err != nil {
		return Dot1RateLimiter{}, mib.Key{}, err
	}
	parent := mib.Key{EntityID: limiter.ParentME}
	switch limiter.TPType {
	case 1:
		parent.ClassID = me.MacBridgeServiceProfileClassID
	case 2:
		parent.ClassID = me.Ieee8021PMapperServiceProfileClassID
	default:
		return Dot1RateLimiter{}, mib.Key{}, fmt.Errorf("dot1 rate limiter %#x has invalid TP type %d",
			instance.EntityID, limiter.TPType)
	}
	if _, exists := instances[parent]; !exists {
		return Dot1RateLimiter{}, mib.Key{}, fmt.Errorf("dot1 rate limiter %#x references missing parent %d/%#x",
			instance.EntityID, parent.ClassID, parent.EntityID)
	}
	pointers := []struct {
		name   string
		field  string
		target *uint16
	}{
		{"upstream unknown-unicast flood", me.Dot1RateLimiter_UpstreamUnicastFloodRatePointer,
			&limiter.UpstreamUnicastFloodTD},
		{"upstream broadcast", me.Dot1RateLimiter_UpstreamBroadcastRatePointer,
			&limiter.UpstreamBroadcastTD},
		{"upstream multicast payload", me.Dot1RateLimiter_UpstreamMulticastPayloadRatePointer,
			&limiter.UpstreamMulticastPayloadTD},
	}
	for _, pointer := range pointers {
		*pointer.target, err = uint16AttributeDefault(instance, pointer.field, 0)
		if err != nil {
			return Dot1RateLimiter{}, mib.Key{}, err
		}
		if *pointer.target == 0 {
			*pointer.target = nullPointer
		}
		if *pointer.target != nullPointer &&
			!hasInstance(instances, me.TrafficDescriptorClassID, *pointer.target) {
			return Dot1RateLimiter{}, mib.Key{}, fmt.Errorf("dot1 rate limiter %#x references missing %s traffic descriptor %#x",
				instance.EntityID, pointer.name, *pointer.target)
		}
	}
	return limiter, parent, nil
}

func sortServiceGraph(graph *ServiceGraph) {
	sort.Slice(graph.UNIs, func(i, j int) bool { return graph.UNIs[i].EntityID < graph.UNIs[j].EntityID })
	sort.Slice(graph.TCONTs, func(i, j int) bool { return graph.TCONTs[i].EntityID < graph.TCONTs[j].EntityID })
	sort.Slice(graph.TrafficDescs, func(i, j int) bool { return graph.TrafficDescs[i].EntityID < graph.TrafficDescs[j].EntityID })
	sort.Slice(graph.Dot1RateLimiters, func(i, j int) bool {
		return graph.Dot1RateLimiters[i].EntityID < graph.Dot1RateLimiters[j].EntityID
	})
	sort.Slice(graph.GEMPorts, func(i, j int) bool { return graph.GEMPorts[i].EntityID < graph.GEMPorts[j].EntityID })
	sort.Slice(graph.Interworking, func(i, j int) bool { return graph.Interworking[i].EntityID < graph.Interworking[j].EntityID })
	sort.Slice(graph.MulticastInterworking, func(i, j int) bool {
		return graph.MulticastInterworking[i].EntityID < graph.MulticastInterworking[j].EntityID
	})
	sort.Slice(graph.MulticastProfiles, func(i, j int) bool {
		return graph.MulticastProfiles[i].EntityID < graph.MulticastProfiles[j].EntityID
	})
	sort.Slice(graph.MulticastSubscribers, func(i, j int) bool {
		return graph.MulticastSubscribers[i].EntityID < graph.MulticastSubscribers[j].EntityID
	})
	sort.Slice(graph.Mappers, func(i, j int) bool { return graph.Mappers[i].EntityID < graph.Mappers[j].EntityID })
	sort.Slice(graph.Bridges, func(i, j int) bool { return graph.Bridges[i].EntityID < graph.Bridges[j].EntityID })
	sort.Slice(graph.VLANFilters, func(i, j int) bool { return graph.VLANFilters[i].EntityID < graph.VLANFilters[j].EntityID })
	sort.Slice(graph.VLANOperations, func(i, j int) bool { return graph.VLANOperations[i].EntityID < graph.VLANOperations[j].EntityID })
	sort.Slice(graph.ExtendedVLANs, func(i, j int) bool { return graph.ExtendedVLANs[i].EntityID < graph.ExtendedVLANs[j].EntityID })
}

func hasInstance(instances map[mib.Key]mib.Instance, classID me.ClassID, entityID uint16) bool {
	_, exists := instances[mib.Key{ClassID: classID, EntityID: entityID}]
	return exists
}

func uint16Attribute(instance mib.Instance, name string) (uint16, error) {
	value, present := instance.Attributes[name]
	if !present {
		return 0, fmt.Errorf("managed entity %d/%#x is missing %s", instance.ClassID, instance.EntityID, name)
	}
	typed, ok := value.(uint16)
	if !ok {
		return 0, fmt.Errorf("managed entity %d/%#x attribute %s has type %T, want uint16",
			instance.ClassID, instance.EntityID, name, value)
	}
	return typed, nil
}

func uint16AttributeDefault(instance mib.Instance, name string, fallback uint16) (uint16, error) {
	if _, present := instance.Attributes[name]; !present {
		return fallback, nil
	}
	return uint16Attribute(instance, name)
}

func uint8Attribute(instance mib.Instance, name string) (uint8, error) {
	value, present := instance.Attributes[name]
	if !present {
		return 0, fmt.Errorf("managed entity %d/%#x is missing %s", instance.ClassID, instance.EntityID, name)
	}
	typed, ok := value.(uint8)
	if !ok {
		return 0, fmt.Errorf("managed entity %d/%#x attribute %s has type %T, want uint8",
			instance.ClassID, instance.EntityID, name, value)
	}
	return typed, nil
}

func uint8AttributeDefault(instance mib.Instance, name string, fallback uint8) (uint8, error) {
	if _, present := instance.Attributes[name]; !present {
		return fallback, nil
	}
	return uint8Attribute(instance, name)
}

func uint32Attribute(instance mib.Instance, name string) (uint32, error) {
	value, present := instance.Attributes[name]
	if !present {
		return 0, fmt.Errorf("managed entity %d/%#x is missing %s", instance.ClassID, instance.EntityID, name)
	}
	typed, ok := value.(uint32)
	if !ok {
		return 0, fmt.Errorf("managed entity %d/%#x attribute %s has type %T, want uint32",
			instance.ClassID, instance.EntityID, name, value)
	}
	return typed, nil
}

func uint32AttributeDefault(instance mib.Instance, name string, fallback uint32) (uint32, error) {
	if _, present := instance.Attributes[name]; !present {
		return fallback, nil
	}
	return uint32Attribute(instance, name)
}

func bytesAttribute(instance mib.Instance, name string, size int) ([]byte, error) {
	value, present := instance.Attributes[name]
	if !present {
		return nil, fmt.Errorf("managed entity %d/%#x is missing %s", instance.ClassID, instance.EntityID, name)
	}
	typed, ok := value.([]byte)
	if !ok || len(typed) != size {
		return nil, fmt.Errorf("managed entity %d/%#x attribute %s has type/length %T/%d, want []byte/%d",
			instance.ClassID, instance.EntityID, name, value, len(typed), size)
	}
	return append([]byte(nil), typed...), nil
}

func bytesAttributeDefault(instance mib.Instance, name string, size int, fallback []byte) ([]byte, error) {
	if _, present := instance.Attributes[name]; !present {
		if len(fallback) != size {
			return nil, fmt.Errorf("invalid default length %d for %s, want %d", len(fallback), name, size)
		}
		return append([]byte(nil), fallback...), nil
	}
	return bytesAttribute(instance, name, size)
}

func tableAttributeDefault(instance mib.Instance, name string, rowSize int) (me.TableRows, error) {
	value, present := instance.Attributes[name]
	if !present || value == nil {
		return me.TableRows{}, nil
	}
	typed, ok := value.(me.TableRows)
	if !ok || typed.NumRows < 0 || len(typed.Rows) != typed.NumRows*rowSize {
		return me.TableRows{}, fmt.Errorf("managed entity %d/%#x attribute %s has invalid table rows",
			instance.ClassID, instance.EntityID, name)
	}
	return me.TableRows{NumRows: typed.NumRows, Rows: append([]byte(nil), typed.Rows...)}, nil
}

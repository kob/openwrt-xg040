// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"fmt"
	"math"
	"net/netip"
	"sort"

	"github.com/xg2010g/airoha-omci/internal/multicast"
)

// MulticastPolicy converts the resolved OMCI graph into the platform-neutral
// policy consumed by the native IGMP/MLD runtime. All ME pointers have already
// been validated by BuildServiceGraph; this conversion additionally resolves
// subscriber MEs to their physical UNI attachment(s).
func (g ServiceGraph) MulticastPolicy() (multicast.Config, error) {
	result := multicast.Config{
		Profiles:    make([]multicast.Profile, 0, len(g.MulticastProfiles)),
		Subscribers: make([]multicast.Subscriber, 0, len(g.MulticastSubscribers)),
	}
	for _, source := range g.MulticastProfiles {
		profile := multicast.Profile{
			EntityID: source.EntityID, IGMPVersion: source.IGMPVersion,
			IGMPFunction: source.IGMPFunction, ImmediateLeave: source.ImmediateLeave != 0,
			UpstreamTCI: source.UpstreamTCI, UpstreamTagControl: source.UpstreamTagControl,
			UpstreamRate: source.UpstreamRate, Robustness: source.Robustness,
			QuerierIPAddress: source.QuerierIPAddress, QueryInterval: source.QueryInterval,
			QueryMaxResponseTime:      source.QueryMaxResponseTime,
			LastMemberQueryInterval:   source.LastMemberQueryInterval,
			UnauthorizedJoinBehaviour: source.UnauthorizedJoinBehaviour != 0,
			DownstreamTagControl:      source.DownstreamTagControl, DownstreamTCI: source.DownstreamTCI,
		}
		var err error
		if profile.DynamicACL, err = convertMulticastACL(source.EntityID, "dynamic", source.DynamicACL); err != nil {
			return multicast.Config{}, err
		}
		if profile.StaticACL, err = convertMulticastACL(source.EntityID, "static", source.StaticACL); err != nil {
			return multicast.Config{}, err
		}
		result.Profiles = append(result.Profiles, profile)
	}

	for _, source := range g.MulticastSubscribers {
		attachments, err := g.multicastAttachments(source)
		if err != nil {
			return multicast.Config{}, err
		}
		subscriber := multicast.Subscriber{
			EntityID: source.EntityID, Attachments: attachments, Profile: source.Profile,
			MaxSimultaneousGroups: source.MaxSimultaneousGroups,
			MaxMulticastBandwidth: source.MaxMulticastBandwidth,
			BandwidthEnforcement:  source.BandwidthEnforcement != 0,
			ServicePackages:       make([]multicast.ServicePackage, 0, len(source.ServicePackages)),
			AllowedPreviews:       make([]multicast.AllowedPreview, 0, len(source.AllowedPreviewGroups)),
		}
		for _, service := range source.ServicePackages {
			subscriber.ServicePackages = append(subscriber.ServicePackages, multicast.ServicePackage{
				RowKey: service.RowKey, VLANID: service.VLANID,
				MaxSimultaneousGroups: service.MaxSimultaneousGroups,
				MaxMulticastBandwidth: service.MaxMulticastBandwidth,
				OperationsProfile:     service.OperationsProfile,
			})
		}
		for _, preview := range source.AllowedPreviewGroups {
			sourceAddress, err := netip.ParseAddr(preview.Source)
			if err != nil {
				return multicast.Config{}, fmt.Errorf("multicast subscriber %#x preview row %d source: %w",
					source.EntityID, preview.RowKey, err)
			}
			destination, err := netip.ParseAddr(preview.Destination)
			if err != nil {
				return multicast.Config{}, fmt.Errorf("multicast subscriber %#x preview row %d destination: %w",
					source.EntityID, preview.RowKey, err)
			}
			subscriber.AllowedPreviews = append(subscriber.AllowedPreviews, multicast.AllowedPreview{
				RowKey: preview.RowKey, Source: sourceAddress, Destination: destination,
				ANIVLAN: preview.ANIVLAN, UNIVLAN: preview.UNIVLAN,
				Duration: preview.Duration, TimeLeft: preview.TimeLeft,
			})
		}
		result.Subscribers = append(result.Subscribers, subscriber)
	}
	return result, nil
}

func convertMulticastACL(profileID uint16, kind string,
	entries []MulticastACLEntry) ([]multicast.ACLEntry, error) {
	result := make([]multicast.ACLEntry, 0, len(entries))
	for _, source := range entries {
		sourceAddress, err := netip.ParseAddr(source.Source)
		if err != nil {
			return nil, fmt.Errorf("multicast profile %#x %s ACL row %d source: %w",
				profileID, kind, source.RowKey, err)
		}
		start, err := netip.ParseAddr(source.Start)
		if err != nil {
			return nil, fmt.Errorf("multicast profile %#x %s ACL row %d start: %w",
				profileID, kind, source.RowKey, err)
		}
		stop, err := netip.ParseAddr(source.Stop)
		if err != nil {
			return nil, fmt.Errorf("multicast profile %#x %s ACL row %d stop: %w",
				profileID, kind, source.RowKey, err)
		}
		result = append(result, multicast.ACLEntry{
			RowKey: source.RowKey, IPVersion: source.IPVersion,
			GEMPortID: source.GEMPortID, VLANID: source.VLANID,
			Source: sourceAddress, Start: start, Stop: stop,
			ImputedBandwidth: source.ImputedBandwidth,
			PreviewLength:    source.PreviewLength, PreviewRepeatTime: source.PreviewRepeatTime,
			PreviewRepeatCount: source.PreviewRepeatCount, PreviewResetTime: source.PreviewResetTime,
		})
	}
	return result, nil
}

func (g ServiceGraph) multicastAttachments(source MulticastSubscriberConfigInfo) ([]multicast.Attachment, error) {
	unis := make(map[uint16]string, len(g.UNIs))
	for _, uni := range g.UNIs {
		unis[uni.EntityID] = uni.Interface
	}
	var attachments []multicast.Attachment
	addBridgeUNI := func(bridge MACBridge, port MACBridgePort) error {
		ifname, exists := unis[port.TP]
		if !exists {
			return fmt.Errorf("multicast subscriber %#x bridge port %#x references missing UNI %#x",
				source.EntityID, port.EntityID, port.TP)
		}
		attachments = append(attachments, multicast.Attachment{
			Interface: ifname, BridgeEntity: bridge.EntityID, BridgePortEntity: port.EntityID,
		})
		return nil
	}

	switch source.METype {
	case 0:
		for _, bridge := range g.Bridges {
			for _, port := range bridge.Ports {
				if port.EntityID == source.EntityID && port.TPType == 1 {
					if err := addBridgeUNI(bridge, port); err != nil {
						return nil, err
					}
				}
			}
		}
	case 1:
		var mapper *PBitMapper
		for index := range g.Mappers {
			if g.Mappers[index].EntityID == source.EntityID {
				mapper = &g.Mappers[index]
				break
			}
		}
		if mapper == nil {
			return nil, fmt.Errorf("multicast subscriber %#x references missing mapper", source.EntityID)
		}
		for _, bridge := range g.Bridges {
			associated := mapper.TPType == 1
			if mapper.TPType == 0 {
				associated = false
				for _, port := range bridge.Ports {
					if port.TPType == 3 && port.TP == mapper.EntityID {
						associated = true
						break
					}
				}
			}
			if !associated {
				continue
			}
			for _, port := range bridge.Ports {
				if port.TPType == 1 && (mapper.TPType == 0 || port.TP == mapper.TPPointer) {
					if err := addBridgeUNI(bridge, port); err != nil {
						return nil, err
					}
				}
			}
		}
		if len(attachments) == 0 && mapper.TPType == 1 {
			ifname, exists := unis[mapper.TPPointer]
			if !exists {
				return nil, fmt.Errorf("multicast subscriber %#x mapper references missing UNI %#x",
					source.EntityID, mapper.TPPointer)
			}
			upstream, err := g.directMulticastMapper(*mapper)
			if err != nil {
				return nil, fmt.Errorf("multicast subscriber %#x direct mapper: %w", source.EntityID, err)
			}
			attachments = append(attachments, multicast.Attachment{
				Interface: ifname, DirectMapper: upstream,
			})
		}
	default:
		return nil, fmt.Errorf("multicast subscriber %#x has invalid ME type %d", source.EntityID, source.METype)
	}
	if len(attachments) == 0 {
		return nil, fmt.Errorf("multicast subscriber %#x has no Ethernet UNI attachment", source.EntityID)
	}
	sort.Slice(attachments, func(i, j int) bool {
		if attachments[i].BridgeEntity != attachments[j].BridgeEntity {
			return attachments[i].BridgeEntity < attachments[j].BridgeEntity
		}
		if attachments[i].BridgePortEntity != attachments[j].BridgePortEntity {
			return attachments[i].BridgePortEntity < attachments[j].BridgePortEntity
		}
		return attachments[i].Interface < attachments[j].Interface
	})
	return attachments, nil
}

func (g ServiceGraph) directMulticastMapper(mapper PBitMapper) (*multicast.UpstreamMapper, error) {
	result := &multicast.UpstreamMapper{UnmarkedFrameOption: mapper.UnmarkedFrameOption,
		DefaultPBit: mapper.DefaultPBit, DSCPToPBit: mapper.DSCPToPBit}
	for priority := range result.GEMPortIDs {
		result.GEMPortIDs[priority] = math.MaxUint16
		pointer := mapper.PBits[priority]
		if pointer == math.MaxUint16 {
			continue
		}
		var interworking *GEMInterworking
		for index := range g.Interworking {
			if g.Interworking[index].EntityID == pointer {
				interworking = &g.Interworking[index]
				break
			}
		}
		if interworking == nil || interworking.Option != 5 ||
			interworking.ServiceProfile != mapper.EntityID {
			return nil, fmt.Errorf("P-bit %d references invalid GEM IW TP %#x", priority, pointer)
		}
		var gem *GEMPort
		for index := range g.GEMPorts {
			if g.GEMPorts[index].EntityID == interworking.GEMPort {
				gem = &g.GEMPorts[index]
				break
			}
		}
		if gem == nil {
			return nil, fmt.Errorf("P-bit %d GEM IW TP %#x references missing GEM CTP %#x",
				priority, pointer, interworking.GEMPort)
		}
		if gem.Direction&2 == 0 {
			return nil, fmt.Errorf("P-bit %d GEM %d has no upstream direction", priority, gem.PortID)
		}
		result.GEMPortIDs[priority] = gem.PortID
	}
	return result, nil
}

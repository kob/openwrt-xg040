// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"time"
)

// ReplicationChange asks the platform backend to start or stop delivery of one
// authorized stream on one subscriber attachment.
type ReplicationChange struct {
	Enable     bool
	Subscriber Subscriber
	Attachment Attachment
	Profile    Profile
	Group      ActiveGroup
}

// UpstreamReport is a normalized join or leave that the backend sends through
// the profile's ANI endpoint and GEM port. The backend performs G.988 upstream
// VLAN tag control while constructing the Ethernet frame.
type UpstreamReport struct {
	Join       bool
	Subscriber Subscriber
	Attachment Attachment
	Profile    Profile
	Group      ActiveGroup
	SourceMAC  [6]byte
	Tags       []VLANTag
}

type RuntimeBackend interface {
	Configure(Config) error
	SetReplication(ReplicationChange) error
	SendReport(UpstreamReport) error
	SendQuery(DownstreamQuery) error
}

// BandwidthKey identifies one replicated downstream stream. A backend reports
// byte-rate samples per key so class 311 can use live traffic while the policy
// engine continues to use imputed bandwidth for admission control.
type BandwidthKey struct {
	SubscriberID uint16
	Interface    string
	Source       netip.Addr
	Group        netip.Addr
	UNIVLAN      VLAN
}

type RuntimeBandwidthSampler interface {
	SampleBandwidth() (map[BandwidthKey]uint32, error)
}

type noopRuntimeBackend struct{}

func (noopRuntimeBackend) Configure(Config) error                 { return nil }
func (noopRuntimeBackend) SetReplication(ReplicationChange) error { return nil }
func (noopRuntimeBackend) SendReport(UpstreamReport) error        { return nil }
func (noopRuntimeBackend) SendQuery(DownstreamQuery) error        { return nil }

type subscriberBinding struct {
	subscriber Subscriber
	attachment Attachment
}

type clientGroupKey struct {
	subscriberID  uint16
	interfaceName string
	client        netip.Addr
	sourceMAC     [6]byte
	vlan          VLAN
	group         netip.Addr
}

type runtimeStreamKey struct {
	subscriberID  uint16
	interfaceName string
	source        netip.Addr
	group         netip.Addr
	vlan          VLAN
}

type clientIdentity struct {
	address netip.Addr
	mac     [6]byte
}

type filterMode uint8

const (
	filterModeInclude filterMode = iota
	filterModeExclude
)

type membershipState struct {
	mode    filterMode
	sources map[netip.Addr]struct{}
}

type runtimeStream struct {
	clients map[clientIdentity]runtimeClient
}

type runtimeClient struct {
	group    ActiveGroup
	tags     []VLANTag
	lastSeen time.Time
}

type pendingLeaveKey struct {
	stream   runtimeStreamKey
	identity clientIdentity
}

type pendingLeave struct {
	binding   subscriberBinding
	profile   Profile
	group     ActiveGroup
	tags      []VLANTag
	remaining uint8
	next      time.Time
}

type generalQuery struct {
	binding subscriberBinding
	profile Profile
	tags    []VLANTag
	next    time.Time
}

type rateKey struct {
	subscriberID  uint16
	interfaceName string
	profileID     uint16
}

type rateWindow struct {
	second int64
	count  uint32
}

type robustnessKey struct {
	interfaceName string
	profileID     uint16
}

// Runtime joins packet-level IGMP/MLD state to the G.988 authorization engine.
// It keeps client membership separately so SPR/proxy profiles report only the
// first join and final leave while class 311 still lists every client.
type Runtime struct {
	mu sync.Mutex

	now         func() time.Time
	backend     RuntimeBackend
	engine      *Engine
	config      Config
	profiles    map[uint16]Profile
	bindings    map[string]subscriberBinding
	memberships map[clientGroupKey]membershipState
	streams     map[runtimeStreamKey]*runtimeStream
	pending     map[pendingLeaveKey]pendingLeave
	queries     []generalQuery
	rates       map[rateKey]rateWindow
	robustness  map[robustnessKey]uint8
	bandwidth   map[BandwidthKey]uint32
}

func NewRuntime(config Config, backend RuntimeBackend, now func() time.Time) (*Runtime, error) {
	if now == nil {
		now = time.Now
	}
	if backend == nil {
		backend = noopRuntimeBackend{}
	}
	result := &Runtime{now: now, backend: backend}
	if err := result.configureLocked(config); err != nil {
		return nil, err
	}
	return result, nil
}

// Configure atomically replaces policy from the runtime's perspective. The
// backend prepares its static filters before active in-memory membership is
// discarded, so an invalid or unrepresentable graph leaves the old policy live.
func (r *Runtime) Configure(config Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.configureLocked(config)
}

func (r *Runtime) configureLocked(config Config) error {
	if err := Validate(config); err != nil {
		return err
	}
	if r.engine != nil && reflect.DeepEqual(config, r.config) {
		return nil
	}
	profiles := make(map[uint16]Profile, len(config.Profiles))
	for _, profile := range config.Profiles {
		profiles[profile.EntityID] = profile
	}
	bindings := make(map[string]subscriberBinding)
	queries := make([]generalQuery, 0)
	now := r.now()
	for _, subscriber := range config.Subscribers {
		if len(subscriber.Attachments) == 0 {
			return fmt.Errorf("multicast subscriber %#x has no attachment", subscriber.EntityID)
		}
		for _, attachment := range subscriber.Attachments {
			if attachment.Interface == "" {
				return fmt.Errorf("multicast subscriber %#x has an empty attachment interface", subscriber.EntityID)
			}
			if previous, exists := bindings[attachment.Interface]; exists {
				return fmt.Errorf("multicast interface %s is shared by subscribers %#x and %#x",
					attachment.Interface, previous.subscriber.EntityID, subscriber.EntityID)
			}
			bindings[attachment.Interface] = subscriberBinding{
				subscriber: subscriber, attachment: attachment,
			}
			queries = append(queries, proxyQueries(subscriber, attachment, profiles, now)...)
		}
	}
	sort.Slice(queries, func(i, j int) bool {
		if queries[i].binding.attachment.Interface != queries[j].binding.attachment.Interface {
			return queries[i].binding.attachment.Interface < queries[j].binding.attachment.Interface
		}
		if queries[i].profile.EntityID != queries[j].profile.EntityID {
			return queries[i].profile.EntityID < queries[j].profile.EntityID
		}
		return vlanTagsKey(queries[i].tags) < vlanTagsKey(queries[j].tags)
	})
	engine, err := New(config, r.now)
	if err != nil {
		return err
	}
	engine.preserveAllowedPreviewExpiries(r.engine)
	if err := r.backend.Configure(config); err != nil {
		return fmt.Errorf("configure multicast backend: %w", err)
	}
	r.engine = engine
	r.config = config
	r.profiles = profiles
	r.bindings = bindings
	r.memberships = make(map[clientGroupKey]membershipState)
	r.streams = make(map[runtimeStreamKey]*runtimeStream)
	r.pending = make(map[pendingLeaveKey]pendingLeave)
	r.queries = queries
	r.rates = make(map[rateKey]rateWindow)
	r.robustness = make(map[robustnessKey]uint8)
	r.bandwidth = nil
	return nil
}

// Handle applies every record in one validated report received from a UNI.
// Queries originating from a subscriber are consumed but never treated as a
// subscription request.
func (r *Runtime) Handle(interfaceName string, message MembershipMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	binding, exists := r.bindings[interfaceName]
	if !exists {
		return fmt.Errorf("multicast report arrived on unmanaged interface %s", interfaceName)
	}
	if message.Downstream {
		if message.Kind == MessageQuery {
			r.learnQueryLocked(binding, message)
		}
		return nil
	}
	if message.Kind != MessageReport {
		return nil
	}
	for _, record := range message.Records {
		if err := r.applyRecordLocked(binding, message, record); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) learnQueryLocked(binding subscriberBinding, message MembershipMessage) {
	if message.QueryRobustness == 0 {
		return
	}
	profileIDs := make(map[uint16]struct{})
	if len(binding.subscriber.ServicePackages) == 0 {
		profileIDs[binding.subscriber.Profile] = struct{}{}
	} else {
		for _, service := range binding.subscriber.ServicePackages {
			if serviceVLANMatches(service.VLANID, message.VLAN) {
				profileIDs[service.OperationsProfile] = struct{}{}
			}
		}
	}
	for profileID := range profileIDs {
		profile, exists := r.profiles[profileID]
		if !exists || profile.Robustness != 0 ||
			(profile.IGMPVersion <= 3) != (message.Version <= 3) {
			continue
		}
		r.robustness[robustnessKey{interfaceName: binding.attachment.Interface,
			profileID: profileID}] = message.QueryRobustness
	}
}

func (r *Runtime) effectiveProfileLocked(interfaceName string, profile Profile) Profile {
	if profile.Robustness != 0 {
		return profile
	}
	if learned := r.robustness[robustnessKey{interfaceName: interfaceName,
		profileID: profile.EntityID}]; learned != 0 {
		profile.Robustness = learned
	}
	return profile
}

func (r *Runtime) applyRecordLocked(binding subscriberBinding, message MembershipMessage,
	record MembershipRecord) error {
	key := clientGroupKey{
		subscriberID: binding.subscriber.EntityID, interfaceName: binding.attachment.Interface,
		client: message.Client, sourceMAC: message.SourceMAC, vlan: message.VLAN, group: record.Group,
	}
	before := cloneMembershipState(r.memberships[key])
	wanted := transitionMembership(before, record)
	beforeForwarding := forwardingSources(before, message.Client.BitLen())
	wantedForwarding := forwardingSources(wanted, message.Client.BitLen())
	afterForwarding := cloneSourceSet(beforeForwarding)
	excluded := sortedSources(wanted.sources)

	for _, source := range sortedSourceDifference(beforeForwarding, wantedForwarding) {
		if err := r.removeLocked(binding, key, source, message.Tags); err != nil {
			return err
		}
		delete(afterForwarding, source)
	}
	for _, source := range sortedSourceDifference(wantedForwarding, beforeForwarding) {
		accepted, err := r.addLocked(binding, key, source, excluded, message.Tags)
		if err != nil {
			return err
		}
		if accepted {
			afterForwarding[source] = struct{}{}
		}
	}
	for _, source := range sortedSourceIntersection(beforeForwarding, wantedForwarding) {
		if err := r.refreshLocked(binding, key, source, excluded, message.Tags); err != nil {
			return err
		}
	}
	if len(afterForwarding) == 0 {
		delete(r.memberships, key)
	} else {
		if wanted.mode == filterModeInclude {
			wanted.sources = afterForwarding
		}
		r.memberships[key] = wanted
	}
	return nil
}

func (r *Runtime) addLocked(binding subscriberBinding, client clientGroupKey,
	source netip.Addr, excluded []netip.Addr, tags []VLANTag) (bool, error) {
	request := Join{SubscriberID: binding.subscriber.EntityID, Interface: binding.attachment.Interface,
		UNIVLAN: client.vlan, Source: source, Group: client.group, Client: client.client}
	streamKey := runtimeStreamKey{subscriberID: request.SubscriberID, interfaceName: request.Interface,
		source: source, group: request.Group, vlan: request.UNIVLAN}
	stream, streamExists := r.streams[streamKey]
	decision := r.engine.Join(request)
	group := activeGroup(request, decision)
	if source.IsUnspecified() {
		group.ExcludedSources = cloneAddresses(excluded)
	}
	profile, profileExists := r.profiles[decision.ProfileID]
	if !decision.Accepted {
		if decision.ForwardUpstream && profileExists {
			if err := r.sendReportLocked(UpstreamReport{Join: true, Subscriber: binding.subscriber,
				Attachment: binding.attachment, Profile: profile, Group: group,
				SourceMAC: client.sourceMAC, Tags: cloneVLANTags(tags)}); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	if !profileExists {
		r.engine.Leave(request)
		return false, fmt.Errorf("authorized multicast decision references missing profile %#x", decision.ProfileID)
	}
	identity := clientIdentity{address: client.client, mac: client.sourceMAC}
	delete(r.pending, pendingLeaveKey{stream: streamKey, identity: identity})
	replicationChanged := !streamExists
	if !streamExists {
		stream = &runtimeStream{clients: make(map[clientIdentity]runtimeClient)}
		stream.clients[identity] = runtimeClient{group: group,
			tags: cloneVLANTags(tags), lastSeen: r.now()}
		replicated := effectiveReplicationGroup(stream)
		change := ReplicationChange{Enable: true, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: replicated}
		if err := r.backend.SetReplication(change); err != nil {
			r.engine.Leave(request)
			return false, fmt.Errorf("enable multicast replication: %w", err)
		}
		r.streams[streamKey] = stream
	} else {
		previous := effectiveReplicationGroup(stream)
		stream.clients[identity] = runtimeClient{group: group,
			tags: cloneVLANTags(tags), lastSeen: r.now()}
		current := effectiveReplicationGroup(stream)
		if !sameReplicationGroup(previous, current) {
			replicationChanged = true
			change := ReplicationChange{Enable: true, Subscriber: binding.subscriber,
				Attachment: binding.attachment, Profile: profile, Group: current}
			if err := r.backend.SetReplication(change); err != nil {
				delete(stream.clients, identity)
				r.engine.Leave(request)
				return false, fmt.Errorf("update multicast replication: %w", err)
			}
		}
	}
	reportGroup := effectiveReplicationGroup(stream)
	if profile.IGMPFunction == 0 {
		reportGroup = group
	} else if aggregate, exists := r.effectiveUpstreamGroup(streamKey); exists {
		reportGroup = aggregate
	}
	if profile.IGMPFunction == 0 || replicationChanged {
		if err := r.sendReportLocked(UpstreamReport{Join: true, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: reportGroup,
			SourceMAC: client.sourceMAC, Tags: cloneVLANTags(tags)}); err != nil {
			return true, err
		}
	}
	return true, nil
}

func (r *Runtime) refreshLocked(binding subscriberBinding, client clientGroupKey,
	source netip.Addr, excluded []netip.Addr, tags []VLANTag) error {
	request := Join{SubscriberID: binding.subscriber.EntityID, Interface: binding.attachment.Interface,
		UNIVLAN: client.vlan, Source: source, Group: client.group, Client: client.client}
	decision := r.engine.Join(request)
	if !decision.Accepted {
		return fmt.Errorf("active multicast stream %s/%s was rejected during refresh", source, client.group)
	}
	profile, exists := r.profiles[decision.ProfileID]
	if !exists {
		return fmt.Errorf("active multicast stream references missing profile %#x", decision.ProfileID)
	}
	streamKey := runtimeStreamKey{subscriberID: request.SubscriberID, interfaceName: request.Interface,
		source: source, group: request.Group, vlan: request.UNIVLAN}
	stream := r.streams[streamKey]
	if stream == nil {
		return fmt.Errorf("active multicast stream %s/%s has no runtime state", source, client.group)
	}
	group := activeGroup(request, decision)
	if source.IsUnspecified() {
		group.ExcludedSources = cloneAddresses(excluded)
	}
	identity := clientIdentity{address: client.client, mac: client.sourceMAC}
	delete(r.pending, pendingLeaveKey{stream: streamKey, identity: identity})
	previous := effectiveReplicationGroup(stream)
	previousClient := stream.clients[identity]
	stream.clients[identity] = runtimeClient{group: group, tags: cloneVLANTags(tags), lastSeen: r.now()}
	current := effectiveReplicationGroup(stream)
	changed := !sameReplicationGroup(previous, current)
	if changed {
		if err := r.backend.SetReplication(ReplicationChange{Enable: true,
			Subscriber: binding.subscriber, Attachment: binding.attachment,
			Profile: profile, Group: current}); err != nil {
			stream.clients[identity] = previousClient
			return fmt.Errorf("update multicast replication: %w", err)
		}
	}
	reportGroup := current
	if profile.IGMPFunction == 0 {
		reportGroup = group
	} else if aggregate, exists := r.effectiveUpstreamGroup(streamKey); exists {
		reportGroup = aggregate
	}
	if profile.IGMPFunction == 0 || changed {
		return r.sendReportLocked(UpstreamReport{Join: true, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: reportGroup,
			SourceMAC: client.sourceMAC, Tags: cloneVLANTags(tags)})
	}
	return nil
}

func (r *Runtime) removeLocked(binding subscriberBinding, client clientGroupKey,
	source netip.Addr, tags []VLANTag) error {
	streamKey := runtimeStreamKey{subscriberID: binding.subscriber.EntityID,
		interfaceName: binding.attachment.Interface, source: source, group: client.group, vlan: client.vlan}
	stream := r.streams[streamKey]
	identity := clientIdentity{address: client.client, mac: client.sourceMAC}
	if stream == nil {
		return nil
	}
	active, exists := stream.clients[identity]
	if !exists {
		return nil
	}
	group := active.group
	profile, profileExists := r.profiles[group.ProfileID]
	if !profileExists {
		return fmt.Errorf("active multicast stream references missing profile %#x", group.ProfileID)
	}
	effectiveProfile := r.effectiveProfileLocked(binding.attachment.Interface, profile)
	last := len(stream.clients) == 1
	if !last || profile.ImmediateLeave {
		return r.finalizeClientLocked(binding, streamKey, identity, profile, active, true)
	}

	query := DownstreamQuery{Subscriber: binding.subscriber, Attachment: binding.attachment,
		Profile: effectiveProfile, Group: group.Group, Source: group.Source, Tags: cloneVLANTags(tags)}
	if group.Source.IsUnspecified() {
		query.Source = netip.Addr{}
	}
	if err := r.backend.SendQuery(query); err != nil {
		return fmt.Errorf("send last-member multicast query: %w", err)
	}
	if profile.IGMPFunction == 0 {
		if err := r.sendReportLocked(UpstreamReport{Join: false, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: group,
			SourceMAC: client.sourceMAC, Tags: cloneVLANTags(tags)}); err != nil {
			return err
		}
	}
	robustness := effectiveRobustness(effectiveProfile)
	r.pending[pendingLeaveKey{stream: streamKey, identity: identity}] = pendingLeave{
		binding: binding, profile: effectiveProfile, group: group, tags: cloneVLANTags(tags),
		remaining: robustness - 1, next: r.now().Add(effectiveLastMemberInterval(effectiveProfile)),
	}
	return nil
}

func (r *Runtime) finalizeClientLocked(binding subscriberBinding, streamKey runtimeStreamKey,
	identity clientIdentity, profile Profile, active runtimeClient, sendReport bool) error {
	stream := r.streams[streamKey]
	if stream == nil {
		return nil
	}
	if _, exists := stream.clients[identity]; !exists {
		return nil
	}
	previousUpstream, hadPreviousUpstream := r.effectiveUpstreamGroup(streamKey)
	last := len(stream.clients) == 1
	previous := effectiveReplicationGroup(stream)
	if last {
		change := ReplicationChange{Enable: false, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: active.group}
		if err := r.backend.SetReplication(change); err != nil {
			return fmt.Errorf("disable multicast replication: %w", err)
		}
	}
	request := Join{SubscriberID: binding.subscriber.EntityID, Interface: binding.attachment.Interface,
		UNIVLAN: active.group.UNIVLAN, Source: active.group.Source, Group: active.group.Group,
		Client: active.group.Client}
	if !r.engine.Leave(request) {
		return fmt.Errorf("active multicast stream %s/%s is missing from policy state",
			active.group.Source, active.group.Group)
	}
	delete(stream.clients, identity)
	delete(r.pending, pendingLeaveKey{stream: streamKey, identity: identity})
	if last {
		delete(r.streams, streamKey)
	} else {
		current := effectiveReplicationGroup(stream)
		if !sameReplicationGroup(previous, current) {
			if err := r.backend.SetReplication(ReplicationChange{Enable: true,
				Subscriber: binding.subscriber, Attachment: binding.attachment,
				Profile: profile, Group: current}); err != nil {
				return fmt.Errorf("update multicast replication after leave: %w", err)
			}
		}
	}
	if sendReport && profile.IGMPFunction == 0 {
		return r.sendReportLocked(UpstreamReport{Join: false, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: active.group,
			SourceMAC: identity.mac, Tags: cloneVLANTags(active.tags)})
	}
	if sendReport && profile.IGMPFunction != 0 && hadPreviousUpstream {
		current, exists := r.effectiveUpstreamGroup(streamKey)
		if exists && sameMembershipGroup(previousUpstream, current) {
			return nil
		}
		if !exists {
			current = emptyMembershipGroup(previousUpstream)
		}
		return r.sendReportLocked(UpstreamReport{Join: exists, Subscriber: binding.subscriber,
			Attachment: binding.attachment, Profile: profile, Group: current,
			SourceMAC: identity.mac, Tags: cloneVLANTags(active.tags)})
	}
	return nil
}

func (r *Runtime) sendReportLocked(report UpstreamReport) error {
	limit := report.Profile.UpstreamRate
	if limit != 0 {
		key := rateKey{subscriberID: report.Subscriber.EntityID,
			interfaceName: report.Attachment.Interface, profileID: report.Profile.EntityID}
		now := r.now().Unix()
		window := r.rates[key]
		if window.second != now {
			window = rateWindow{second: now}
		}
		if window.count >= limit {
			r.rates[key] = window
			return nil
		}
		window.count++
		r.rates[key] = window
	}
	if err := r.backend.SendReport(report); err != nil {
		return fmt.Errorf("send upstream multicast report: %w", err)
	}
	return nil
}

// Expire advances preview, proxy-query, membership-ageing and delayed-leave
// timers. The daemon calls it frequently enough to honour the 0.1 s units used
// by the class-309 last-member query interval.
func (r *Runtime) Expire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for _, group := range r.engine.Expire() {
		streamKey := runtimeStreamKey{subscriberID: subscriberForInterface(r.bindings, group.Interface),
			interfaceName: group.Interface, source: group.Source, group: group.Group, vlan: group.UNIVLAN}
		stream := r.streams[streamKey]
		if stream == nil {
			continue
		}
		previousUpstream, hadPreviousUpstream := r.effectiveUpstreamGroup(streamKey)
		var identity clientIdentity
		var active runtimeClient
		for candidate := range stream.clients {
			if candidate.address == group.Client {
				identity = candidate
				active = stream.clients[candidate]
				break
			}
		}
		delete(r.pending, pendingLeaveKey{stream: streamKey, identity: identity})
		previous := effectiveReplicationGroup(stream)
		delete(stream.clients, identity)
		binding := r.bindings[group.Interface]
		profile := r.profiles[group.ProfileID]
		if len(stream.clients) == 0 {
			if err := r.backend.SetReplication(ReplicationChange{Enable: false,
				Subscriber: binding.subscriber, Attachment: binding.attachment,
				Profile: profile, Group: group}); err != nil {
				return fmt.Errorf("expire multicast replication: %w", err)
			}
			delete(r.streams, streamKey)
		} else {
			current := effectiveReplicationGroup(stream)
			if !sameReplicationGroup(previous, current) {
				if err := r.backend.SetReplication(ReplicationChange{Enable: true,
					Subscriber: binding.subscriber, Attachment: binding.attachment,
					Profile: profile, Group: current}); err != nil {
					return fmt.Errorf("update multicast replication after expiry: %w", err)
				}
			}
		}
		for key, membership := range r.memberships {
			if key.subscriberID == binding.subscriber.EntityID && key.interfaceName == group.Interface &&
				key.client == group.Client && key.vlan == group.UNIVLAN && key.group == group.Group {
				if membership.mode == filterModeExclude && group.Source.IsUnspecified() {
					delete(r.memberships, key)
					continue
				}
				delete(membership.sources, group.Source)
				if len(membership.sources) == 0 {
					delete(r.memberships, key)
				} else {
					r.memberships[key] = membership
				}
			}
		}
		if profile.IGMPFunction != 0 && hadPreviousUpstream {
			current, exists := r.effectiveUpstreamGroup(streamKey)
			if exists && sameMembershipGroup(previousUpstream, current) {
				continue
			}
			if !exists {
				current = emptyMembershipGroup(previousUpstream)
			}
			if err := r.sendReportLocked(UpstreamReport{Join: exists, Subscriber: binding.subscriber,
				Attachment: binding.attachment, Profile: profile, Group: current,
				SourceMAC: identity.mac, Tags: cloneVLANTags(active.tags)}); err != nil {
				return err
			}
		} else if profile.IGMPFunction == 0 {
			if err := r.sendReportLocked(UpstreamReport{Join: false, Subscriber: binding.subscriber,
				Attachment: binding.attachment, Profile: profile, Group: group, SourceMAC: identity.mac,
				Tags: cloneVLANTags(active.tags)}); err != nil {
				return err
			}
		}
	}
	if err := r.runGeneralQueriesLocked(now); err != nil {
		return err
	}
	if err := r.runPendingLeavesLocked(now); err != nil {
		return err
	}
	if err := r.expireProxyMembershipsLocked(now); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) runGeneralQueriesLocked(now time.Time) error {
	for index := range r.queries {
		query := &r.queries[index]
		if query.next.After(now) {
			continue
		}
		profile := r.effectiveProfileLocked(query.binding.attachment.Interface, query.profile)
		if err := r.backend.SendQuery(DownstreamQuery{Subscriber: query.binding.subscriber,
			Attachment: query.binding.attachment, Profile: profile,
			Tags: cloneVLANTags(query.tags)}); err != nil {
			return fmt.Errorf("send general multicast query on %s: %w",
				query.binding.attachment.Interface, err)
		}
		query.next = now.Add(secondsDuration(uint64(effectiveQueryInterval(profile))))
	}
	return nil
}

func (r *Runtime) runPendingLeavesLocked(now time.Time) error {
	keys := make([]pendingLeaveKey, 0, len(r.pending))
	for key := range r.pending {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].stream.interfaceName != keys[j].stream.interfaceName {
			return keys[i].stream.interfaceName < keys[j].stream.interfaceName
		}
		if comparison := keys[i].stream.group.Compare(keys[j].stream.group); comparison != 0 {
			return comparison < 0
		}
		return keys[i].identity.address.Compare(keys[j].identity.address) < 0
	})
	for _, key := range keys {
		pending, exists := r.pending[key]
		if !exists || pending.next.After(now) {
			continue
		}
		stream := r.streams[key.stream]
		if stream == nil {
			delete(r.pending, key)
			continue
		}
		active, exists := stream.clients[key.identity]
		if !exists {
			delete(r.pending, key)
			continue
		}
		if pending.remaining != 0 {
			query := DownstreamQuery{Subscriber: pending.binding.subscriber,
				Attachment: pending.binding.attachment, Profile: pending.profile,
				Group: pending.group.Group, Source: pending.group.Source, Tags: cloneVLANTags(pending.tags)}
			if query.Source.IsUnspecified() {
				query.Source = netip.Addr{}
			}
			if err := r.backend.SendQuery(query); err != nil {
				return fmt.Errorf("repeat last-member multicast query: %w", err)
			}
			pending.remaining--
			pending.next = now.Add(effectiveLastMemberInterval(pending.profile))
			r.pending[key] = pending
			continue
		}
		sendReport := pending.profile.IGMPFunction != 0
		if err := r.finalizeClientLocked(pending.binding, key.stream, key.identity,
			pending.profile, active, sendReport); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) expireProxyMembershipsLocked(now time.Time) error {
	type staleClient struct {
		streamKey runtimeStreamKey
		identity  clientIdentity
		active    runtimeClient
		profile   Profile
		binding   subscriberBinding
	}
	var stale []staleClient
	for streamKey, stream := range r.streams {
		binding := r.bindings[streamKey.interfaceName]
		for identity, active := range stream.clients {
			profile := r.effectiveProfileLocked(streamKey.interfaceName,
				r.profiles[active.group.ProfileID])
			if profile.IGMPFunction != 2 {
				continue
			}
			if _, pending := r.pending[pendingLeaveKey{stream: streamKey, identity: identity}]; pending {
				continue
			}
			interval := membershipInterval(profile)
			if !active.lastSeen.Add(interval).After(now) {
				stale = append(stale, staleClient{streamKey: streamKey, identity: identity,
					active: active, profile: profile, binding: binding})
			}
		}
	}
	for _, client := range stale {
		if err := r.finalizeClientLocked(client.binding, client.streamKey, client.identity,
			client.profile, client.active, true); err != nil {
			return fmt.Errorf("expire proxy multicast membership: %w", err)
		}
	}
	return nil
}

func (r *Runtime) Monitor(subscriberID uint16) Monitor {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.engine.Monitor(subscriberID)
	if _, available := r.backend.(RuntimeBandwidthSampler); !available {
		return result
	}
	seen := make(map[BandwidthKey]struct{}, len(result.Groups))
	var bandwidth uint64
	for _, group := range result.Groups {
		key := BandwidthKey{SubscriberID: subscriberID, Interface: group.Interface,
			Source: group.Source, Group: group.Group, UNIVLAN: group.UNIVLAN}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		value, sampled := r.bandwidth[key]
		if !sampled {
			value = group.ImputedBandwidth
		}
		bandwidth += uint64(value)
	}
	if bandwidth > math.MaxUint32 {
		result.CurrentBandwidth = math.MaxUint32
	} else {
		result.CurrentBandwidth = uint32(bandwidth)
	}
	return result
}

// SampleBandwidth refreshes the live class-311 rates. A failed or incomplete
// sample is discarded so Monitor falls back to the configured imputed value
// instead of publishing stale traffic indefinitely.
func (r *Runtime) SampleBandwidth() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sampler, available := r.backend.(RuntimeBandwidthSampler)
	if !available {
		r.bandwidth = nil
		return nil
	}
	values, err := sampler.SampleBandwidth()
	if err != nil {
		r.bandwidth = nil
		return err
	}
	r.bandwidth = make(map[BandwidthKey]uint32, len(values))
	for key, value := range values {
		r.bandwidth[key] = value
	}
	return nil
}

func (r *Runtime) AllowedPreviewTimers(subscriberID uint16) []AllowedPreviewTimer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engine.AllowedPreviewTimers(subscriberID)
}

func (r *Runtime) SubscriberIDs() []uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[uint16]struct{}, len(r.config.Subscribers))
	for _, subscriber := range r.config.Subscribers {
		seen[subscriber.EntityID] = struct{}{}
	}
	result := make([]uint16, 0, len(seen))
	for entityID := range seen {
		result = append(result, entityID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (r *Runtime) Interfaces() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, 0, len(r.bindings))
	for interfaceName := range r.bindings {
		result = append(result, interfaceName)
	}
	sort.Strings(result)
	return result
}

func activeGroup(request Join, decision Decision) ActiveGroup {
	return ActiveGroup{
		Interface: request.Interface, Source: request.Source, Group: request.Group,
		Client: request.Client, UNIVLAN: request.UNIVLAN, ANIVLAN: decision.ANIVLAN,
		ProfileID: decision.ProfileID, ACLRowKey: decision.ACLRowKey,
		GEMPortID: decision.GEMPortID, ImputedBandwidth: decision.ImputedBandwidth,
		PreviewUntil: decision.PreviewUntil,
	}
}

func transitionMembership(before membershipState, record MembershipRecord) membershipState {
	result := cloneMembershipState(before)
	sources := sourceSet(record.Sources)
	switch record.Type {
	case ModeIsInclude, ChangeToIncludeMode:
		return membershipState{mode: filterModeInclude, sources: sources}
	case ModeIsExclude, ChangeToExcludeMode:
		return membershipState{mode: filterModeExclude, sources: sources}
	case AllowNewSources:
		if result.mode == filterModeExclude {
			for source := range sources {
				delete(result.sources, source)
			}
		} else {
			for source := range sources {
				result.sources[source] = struct{}{}
			}
		}
	case BlockOldSources:
		if result.mode == filterModeExclude {
			for source := range sources {
				result.sources[source] = struct{}{}
			}
		} else {
			for source := range sources {
				delete(result.sources, source)
			}
		}
	}
	return result
}

func forwardingSources(state membershipState, bitLength int) map[netip.Addr]struct{} {
	if state.mode != filterModeExclude {
		return cloneSourceSet(state.sources)
	}
	wildcard := netip.IPv4Unspecified()
	if bitLength == 128 {
		wildcard = netip.IPv6Unspecified()
	}
	return map[netip.Addr]struct{}{wildcard: {}}
}

func cloneMembershipState(state membershipState) membershipState {
	return membershipState{mode: state.mode, sources: cloneSourceSet(state.sources)}
}

func sourceSet(sources []netip.Addr) map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{}, len(sources))
	for _, source := range sources {
		result[source] = struct{}{}
	}
	return result
}

func cloneSourceSet(source map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{}, len(source))
	for address := range source {
		result[address] = struct{}{}
	}
	return result
}

func sortedSources(source map[netip.Addr]struct{}) []netip.Addr {
	result := make([]netip.Addr, 0, len(source))
	for address := range source {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result
}

func cloneAddresses(source []netip.Addr) []netip.Addr {
	return append([]netip.Addr(nil), source...)
}

func effectiveReplicationGroup(stream *runtimeStream) ActiveGroup {
	var result ActiveGroup
	first := true
	var excluded map[netip.Addr]struct{}
	for _, client := range stream.clients {
		if first {
			result = client.group
			first = false
		}
		if !client.group.Source.IsUnspecified() {
			continue
		}
		candidate := sourceSet(client.group.ExcludedSources)
		if excluded == nil {
			excluded = candidate
			continue
		}
		for source := range excluded {
			if _, exists := candidate[source]; !exists {
				delete(excluded, source)
			}
		}
	}
	result.ExcludedSources = sortedSources(excluded)
	return result
}

func (r *Runtime) effectiveUpstreamGroup(wanted runtimeStreamKey) (ActiveGroup, bool) {
	var result ActiveGroup
	var included map[netip.Addr]struct{}
	var excluded map[netip.Addr]struct{}
	hasExclude := false
	for key, stream := range r.streams {
		if key.subscriberID != wanted.subscriberID || key.interfaceName != wanted.interfaceName ||
			key.group != wanted.group || key.vlan != wanted.vlan || len(stream.clients) == 0 {
			continue
		}
		current := effectiveReplicationGroup(stream)
		if !result.Group.IsValid() {
			result = current
		}
		if key.source.IsUnspecified() {
			if !hasExclude {
				excluded = sourceSet(current.ExcludedSources)
				hasExclude = true
			} else {
				for source := range excluded {
					if _, exists := sourceSet(current.ExcludedSources)[source]; !exists {
						delete(excluded, source)
					}
				}
			}
			continue
		}
		if included == nil {
			included = make(map[netip.Addr]struct{})
		}
		included[key.source] = struct{}{}
	}
	if !result.Group.IsValid() {
		return ActiveGroup{}, false
	}
	if hasExclude {
		for source := range included {
			delete(excluded, source)
		}
		if result.Group.Is4() {
			result.Source = netip.IPv4Unspecified()
		} else {
			result.Source = netip.IPv6Unspecified()
		}
		result.IncludedSources = nil
		result.ExcludedSources = sortedSources(excluded)
		return result, true
	}
	result.IncludedSources = sortedSources(included)
	result.ExcludedSources = nil
	result.Source = result.IncludedSources[0]
	return result, true
}

func emptyMembershipGroup(previous ActiveGroup) ActiveGroup {
	result := previous
	if result.Group.Is4() {
		result.Source = netip.IPv4Unspecified()
	} else {
		result.Source = netip.IPv6Unspecified()
	}
	result.IncludedSources = nil
	result.ExcludedSources = nil
	return result
}

func sameMembershipGroup(left, right ActiveGroup) bool {
	if left.Source.IsUnspecified() != right.Source.IsUnspecified() ||
		len(left.IncludedSources) != len(right.IncludedSources) ||
		len(left.ExcludedSources) != len(right.ExcludedSources) {
		return false
	}
	for index := range left.IncludedSources {
		if left.IncludedSources[index] != right.IncludedSources[index] {
			return false
		}
	}
	for index := range left.ExcludedSources {
		if left.ExcludedSources[index] != right.ExcludedSources[index] {
			return false
		}
	}
	return true
}

func sameReplicationGroup(left, right ActiveGroup) bool {
	if left.Source != right.Source || left.Group != right.Group || left.UNIVLAN != right.UNIVLAN ||
		left.ANIVLAN != right.ANIVLAN || left.GEMPortID != right.GEMPortID ||
		len(left.IncludedSources) != len(right.IncludedSources) ||
		len(left.ExcludedSources) != len(right.ExcludedSources) {
		return false
	}
	for index := range left.IncludedSources {
		if left.IncludedSources[index] != right.IncludedSources[index] {
			return false
		}
	}
	for index := range left.ExcludedSources {
		if left.ExcludedSources[index] != right.ExcludedSources[index] {
			return false
		}
	}
	return true
}

func sortedSourceDifference(left, right map[netip.Addr]struct{}) []netip.Addr {
	var result []netip.Addr
	for source := range left {
		if _, exists := right[source]; !exists {
			result = append(result, source)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result
}

func sortedSourceIntersection(left, right map[netip.Addr]struct{}) []netip.Addr {
	var result []netip.Addr
	for source := range left {
		if _, exists := right[source]; exists {
			result = append(result, source)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result
}

func subscriberForInterface(bindings map[string]subscriberBinding, interfaceName string) uint16 {
	return bindings[interfaceName].subscriber.EntityID
}

func proxyQueries(subscriber Subscriber, attachment Attachment, profiles map[uint16]Profile,
	now time.Time) []generalQuery {
	binding := subscriberBinding{subscriber: subscriber, attachment: attachment}
	seen := make(map[string]struct{})
	var result []generalQuery
	appendQuery := func(profile Profile, tags []VLANTag) {
		if profile.IGMPFunction != 2 {
			return
		}
		key := fmt.Sprintf("%d:%s", profile.EntityID, vlanTagsKey(tags))
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, generalQuery{binding: binding, profile: profile,
			tags: cloneVLANTags(tags), next: now})
	}
	if len(subscriber.ServicePackages) == 0 {
		appendQuery(profiles[subscriber.Profile], proxyQueryTags(profiles[subscriber.Profile], nil))
		return result
	}
	for index := range subscriber.ServicePackages {
		service := &subscriber.ServicePackages[index]
		profile := profiles[service.OperationsProfile]
		appendQuery(profile, proxyQueryTags(profile, service))
	}
	return result
}

func proxyQueryTags(profile Profile, service *ServicePackage) []VLANTag {
	if service != nil {
		switch service.VLANID {
		case 4096:
			return nil
		case 4097, 0xffff:
			// The exact subscriber VID is unspecified. The profile TCI is the
			// only deterministic value available to the proxy querier.
		default:
			return []VLANTag{{TPID: 0x8100, TCI: profile.DownstreamTCI&0xf000 | service.VLANID}}
		}
	}
	if profile.DownstreamTagControl >= 2 {
		return []VLANTag{{TPID: 0x8100, TCI: profile.DownstreamTCI}}
	}
	return nil
}

func vlanTagsKey(tags []VLANTag) string {
	result := ""
	for _, tag := range tags {
		result += fmt.Sprintf("%04x.%04x/", tag.TPID, tag.TCI)
	}
	return result
}

func cloneVLANTags(tags []VLANTag) []VLANTag {
	return append([]VLANTag(nil), tags...)
}

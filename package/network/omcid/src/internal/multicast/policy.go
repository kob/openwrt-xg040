// SPDX-License-Identifier: Apache-2.0

// Package multicast implements the G.988 multicast authorization policy. It
// deliberately contains no Linux or Airoha-specific packet I/O so the policy
// can be shared by the OMCI engine and the native IGMP/MLD backend.
package multicast

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type VLAN struct {
	Tagged bool
	ID     uint16
}

type ACLEntry struct {
	RowKey             uint16
	IPVersion          uint8
	GEMPortID          uint16
	VLANID             uint16
	Source             netip.Addr
	Start              netip.Addr
	Stop               netip.Addr
	ImputedBandwidth   uint32
	PreviewLength      uint16
	PreviewRepeatTime  uint16
	PreviewRepeatCount uint16
	PreviewResetTime   uint16
}

type Profile struct {
	EntityID                  uint16
	IGMPVersion               uint8
	IGMPFunction              uint8
	ImmediateLeave            bool
	UpstreamTCI               uint16
	UpstreamTagControl        uint8
	UpstreamRate              uint32
	Robustness                uint8
	QuerierIPAddress          uint32
	QueryInterval             uint32
	QueryMaxResponseTime      uint32
	LastMemberQueryInterval   uint32
	UnauthorizedJoinBehaviour bool
	DownstreamTagControl      uint8
	DownstreamTCI             uint16
	DynamicACL                []ACLEntry
	StaticACL                 []ACLEntry
}

type ServicePackage struct {
	RowKey                uint16
	VLANID                uint16
	MaxSimultaneousGroups uint16
	MaxMulticastBandwidth uint32
	OperationsProfile     uint16
}

type AllowedPreview struct {
	RowKey      uint16
	Source      netip.Addr
	Destination netip.Addr
	ANIVLAN     uint16
	UNIVLAN     uint16
	Duration    uint16
	TimeLeft    uint16
}

type Attachment struct {
	Interface        string
	BridgeEntity     uint16
	BridgePortEntity uint16
	DirectMapper     *UpstreamMapper
}

// UpstreamMapper is the resolved, platform-neutral subset of class 130 needed
// to inject an IGMP/MLD report directly into the PON netdev with the GEM mark
// expected by the Airoha data path.
type UpstreamMapper struct {
	GEMPortIDs          [8]uint16
	UnmarkedFrameOption uint8
	DefaultPBit         uint8
	DSCPToPBit          [64]uint8
}

type Subscriber struct {
	EntityID              uint16
	Attachments           []Attachment
	Profile               uint16
	MaxSimultaneousGroups uint16
	MaxMulticastBandwidth uint32
	BandwidthEnforcement  bool
	ServicePackages       []ServicePackage
	AllowedPreviews       []AllowedPreview
}

type Config struct {
	Profiles    []Profile
	Subscribers []Subscriber
}

type Join struct {
	SubscriberID uint16
	Interface    string
	UNIVLAN      VLAN
	Source       netip.Addr
	Group        netip.Addr
	Client       netip.Addr
}

type Reason string

const (
	ReasonAuthorized        Reason = "authorized"
	ReasonAllowedPreview    Reason = "allowed-preview"
	ReasonPreview           Reason = "preview"
	ReasonUnauthorized      Reason = "unauthorized"
	ReasonGroupLimit        Reason = "group-limit"
	ReasonBandwidthExceeded Reason = "bandwidth-exceeded"
	ReasonPreviewExhausted  Reason = "preview-exhausted"
	ReasonPreviewInterval   Reason = "preview-interval"
	ReasonUnknownSubscriber Reason = "unknown-subscriber"
)

type Decision struct {
	Accepted          bool
	ForwardUpstream   bool
	Replicate         bool
	Reason            Reason
	ProfileID         uint16
	ACLRowKey         uint16
	GEMPortID         uint16
	ANIVLAN           uint16
	ImputedBandwidth  uint32
	BandwidthExceeded bool
	PreviewUntil      time.Time
}

type ActiveGroup struct {
	Interface        string
	Source           netip.Addr
	IncludedSources  []netip.Addr
	ExcludedSources  []netip.Addr
	Group            netip.Addr
	Client           netip.Addr
	UNIVLAN          VLAN
	ANIVLAN          uint16
	ProfileID        uint16
	ACLRowKey        uint16
	GEMPortID        uint16
	ImputedBandwidth uint32
	TimeSinceJoin    uint32
	PreviewUntil     time.Time
}

type Monitor struct {
	CurrentBandwidth  uint32
	JoinMessages      uint32
	BandwidthExceeded uint32
	Groups            []ActiveGroup
}

// AllowedPreviewTimer is the ONU-owned live portion of one class-310 allowed
// preview row. TimeLeft is rounded up to whole minutes until the deadline and
// becomes zero only when the logical row has expired.
type AllowedPreviewTimer struct {
	RowKey   uint16
	Duration uint16
	TimeLeft uint16
}

type AllowedPreviewSnapshot struct {
	MIBDataSync uint8
	Timers      []AllowedPreviewTimer
}

// Controller supplies the live class-311 view maintained by the native
// IGMP/MLD runtime.
type Controller interface {
	SubscriberMonitor(entityID uint16) (Monitor, error)
}

// PreviewController supplies the live ONU-owned time-left field for class 310.
// It is separate from Controller so a platform may expose class-311 monitoring
// before it implements allowed-preview timer synchronization.
type PreviewController interface {
	AllowedPreviewStatus(entityID uint16) (AllowedPreviewSnapshot, error)
}

type compiledConfig struct {
	profiles    map[uint16]Profile
	subscribers map[uint16]compiledSubscriber
}

type compiledSubscriber struct {
	Subscriber
	previewExpiry map[uint16]time.Time
}

type activeKey struct {
	interfaceName string
	source        netip.Addr
	group         netip.Addr
	vlan          VLAN
	client        netip.Addr
}

type streamKey struct {
	interfaceName string
	source        netip.Addr
	group         netip.Addr
	vlan          VLAN
}

type activeState struct {
	ActiveGroup
	joinedAt   time.Time
	reason     Reason
	packageID  uint16
	hasPackage bool
}

type previewKey struct {
	subscriber uint16
	profile    uint16
	row        uint16
	source     netip.Addr
	group      netip.Addr
}

type previewState struct {
	count       uint16
	nextAllowed time.Time
	lastReset   time.Time
}

type subscriberState struct {
	groups            map[activeKey]activeState
	joinMessages      uint32
	bandwidthExceeded uint32
}

type Engine struct {
	mu       sync.Mutex
	now      func() time.Time
	config   compiledConfig
	state    map[uint16]*subscriberState
	previews map[previewKey]previewState
}

func New(config Config, now func() time.Time) (*Engine, error) {
	if now == nil {
		now = time.Now
	}
	compiled, err := compile(config, now())
	if err != nil {
		return nil, err
	}
	return &Engine{
		now: now, config: compiled, state: make(map[uint16]*subscriberState),
		previews: make(map[previewKey]previewState),
	}, nil
}

// preserveAllowedPreviewExpiries carries exact deadlines across a policy
// reload when the complete class-310 row is unchanged. Without this, an
// unrelated MIB update would restart every preview timer from its originally
// committed, minute-granularity time-left value.
func (e *Engine) preserveAllowedPreviewExpiries(previous *Engine) {
	if previous == nil {
		return
	}
	previous.mu.Lock()
	defer previous.mu.Unlock()
	for entityID, current := range e.config.subscribers {
		old, exists := previous.config.subscribers[entityID]
		if !exists {
			continue
		}
		oldRows := make(map[uint16]AllowedPreview, len(old.AllowedPreviews))
		for _, preview := range old.AllowedPreviews {
			oldRows[preview.RowKey] = preview
		}
		for _, preview := range current.AllowedPreviews {
			if oldRows[preview.RowKey] != preview {
				continue
			}
			if deadline, timed := old.previewExpiry[preview.RowKey]; timed {
				current.previewExpiry[preview.RowKey] = deadline
			}
		}
		e.config.subscribers[entityID] = current
	}
}

func compile(config Config, now time.Time) (compiledConfig, error) {
	result := compiledConfig{
		profiles:    make(map[uint16]Profile, len(config.Profiles)),
		subscribers: make(map[uint16]compiledSubscriber, len(config.Subscribers)),
	}
	for _, profile := range config.Profiles {
		if profile.EntityID == 0 || profile.EntityID == math.MaxUint16 {
			return compiledConfig{}, fmt.Errorf("multicast profile has reserved entity ID %#x", profile.EntityID)
		}
		if profile.IGMPVersion != 1 && profile.IGMPVersion != 2 && profile.IGMPVersion != 3 &&
			profile.IGMPVersion != 16 && profile.IGMPVersion != 17 {
			return compiledConfig{}, fmt.Errorf("multicast profile %#x has invalid IGMP/MLD version %d",
				profile.EntityID, profile.IGMPVersion)
		}
		if profile.IGMPFunction > 2 || profile.UpstreamTagControl > 3 || profile.DownstreamTagControl > 7 {
			return compiledConfig{}, fmt.Errorf("multicast profile %#x has invalid function or tag control",
				profile.EntityID)
		}
		if _, exists := result.profiles[profile.EntityID]; exists {
			return compiledConfig{}, fmt.Errorf("duplicate multicast profile %#x", profile.EntityID)
		}
		for _, entries := range [][]ACLEntry{profile.DynamicACL, profile.StaticACL} {
			for _, entry := range entries {
				if err := validateACL(entry); err != nil {
					return compiledConfig{}, fmt.Errorf("multicast profile %#x: %w", profile.EntityID, err)
				}
			}
		}
		sort.Slice(profile.DynamicACL, func(i, j int) bool {
			return profile.DynamicACL[i].RowKey < profile.DynamicACL[j].RowKey
		})
		sort.Slice(profile.StaticACL, func(i, j int) bool {
			return profile.StaticACL[i].RowKey < profile.StaticACL[j].RowKey
		})
		result.profiles[profile.EntityID] = profile
	}

	for _, subscriber := range config.Subscribers {
		if _, exists := result.subscribers[subscriber.EntityID]; exists {
			return compiledConfig{}, fmt.Errorf("duplicate multicast subscriber %#x", subscriber.EntityID)
		}
		sort.Slice(subscriber.ServicePackages, func(i, j int) bool {
			return subscriber.ServicePackages[i].RowKey < subscriber.ServicePackages[j].RowKey
		})
		seenPackages := make(map[uint16]struct{}, len(subscriber.ServicePackages))
		for _, service := range subscriber.ServicePackages {
			if _, exists := seenPackages[service.RowKey]; exists {
				return compiledConfig{}, fmt.Errorf("multicast subscriber %#x repeats service row %d",
					subscriber.EntityID, service.RowKey)
			}
			seenPackages[service.RowKey] = struct{}{}
			if !validServiceVLAN(service.VLANID) {
				return compiledConfig{}, fmt.Errorf("multicast subscriber %#x service row %d has invalid VLAN %d",
					subscriber.EntityID, service.RowKey, service.VLANID)
			}
			if _, exists := result.profiles[service.OperationsProfile]; !exists {
				return compiledConfig{}, fmt.Errorf("multicast subscriber %#x service row %d references missing profile %#x",
					subscriber.EntityID, service.RowKey, service.OperationsProfile)
			}
		}
		if len(subscriber.ServicePackages) == 0 {
			if _, exists := result.profiles[subscriber.Profile]; !exists {
				return compiledConfig{}, fmt.Errorf("multicast subscriber %#x references missing profile %#x",
					subscriber.EntityID, subscriber.Profile)
			}
		}

		expiry := make(map[uint16]time.Time, len(subscriber.AllowedPreviews))
		seenPreviews := make(map[uint16]struct{}, len(subscriber.AllowedPreviews))
		for _, preview := range subscriber.AllowedPreviews {
			if _, exists := seenPreviews[preview.RowKey]; exists {
				return compiledConfig{}, fmt.Errorf("multicast subscriber %#x repeats preview row %d",
					subscriber.EntityID, preview.RowKey)
			}
			seenPreviews[preview.RowKey] = struct{}{}
			if err := validateAllowedPreview(preview); err != nil {
				return compiledConfig{}, fmt.Errorf("multicast subscriber %#x: %w", subscriber.EntityID, err)
			}
			if preview.Duration != 0 && preview.TimeLeft != 0 {
				expiry[preview.RowKey] = now.Add(time.Duration(preview.TimeLeft) * time.Minute)
			}
		}
		result.subscribers[subscriber.EntityID] = compiledSubscriber{
			Subscriber: subscriber, previewExpiry: expiry,
		}
	}
	return result, nil
}

// Validate compiles a policy without starting runtime state. It is used at the
// transactional platform boundary so an invalid policy is rejected before the
// corresponding OMCI mutation is committed.
func Validate(config Config) error {
	_, err := compile(config, time.Now())
	return err
}

func validateACL(entry ACLEntry) error {
	if entry.RowKey > 1023 || entry.GEMPortID > 4095 ||
		(entry.VLANID == 4096 || entry.VLANID > 4097 && entry.VLANID != math.MaxUint16) {
		return fmt.Errorf("ACL row %d has an invalid key, GEM Port-ID or ANI VLAN", entry.RowKey)
	}
	if entry.IPVersion != 4 && entry.IPVersion != 6 {
		return fmt.Errorf("ACL row %d has invalid IP version %d", entry.RowKey, entry.IPVersion)
	}
	if !addressVersion(entry.Start, entry.IPVersion) || !addressVersion(entry.Stop, entry.IPVersion) ||
		!entry.Start.IsMulticast() || !entry.Stop.IsMulticast() || entry.Start.Compare(entry.Stop) > 0 {
		return fmt.Errorf("ACL row %d has invalid multicast range %s..%s", entry.RowKey, entry.Start, entry.Stop)
	}
	if entry.Source.IsValid() && !entry.Source.IsUnspecified() && !addressVersion(entry.Source, entry.IPVersion) {
		return fmt.Errorf("ACL row %d source %s does not match IP version %d", entry.RowKey, entry.Source, entry.IPVersion)
	}
	if entry.PreviewResetTime > 24 && entry.PreviewResetTime < 241 {
		return fmt.Errorf("ACL row %d has reserved preview reset time %d", entry.RowKey, entry.PreviewResetTime)
	}
	return nil
}

func validateAllowedPreview(preview AllowedPreview) error {
	if preview.RowKey > 1023 || preview.ANIVLAN > 4095 || preview.UNIVLAN > 4095 {
		return fmt.Errorf("allowed-preview row %d has an invalid key or VLAN", preview.RowKey)
	}
	if !preview.Destination.IsValid() || !preview.Destination.IsMulticast() {
		return fmt.Errorf("allowed-preview row %d has invalid destination %s", preview.RowKey, preview.Destination)
	}
	if preview.Source.IsValid() && !preview.Source.IsUnspecified() &&
		preview.Source.BitLen() != preview.Destination.BitLen() {
		return fmt.Errorf("allowed-preview row %d source and destination use different IP versions", preview.RowKey)
	}
	if preview.Duration != 0 && preview.TimeLeft > preview.Duration {
		return fmt.Errorf("allowed-preview row %d time left exceeds duration", preview.RowKey)
	}
	return nil
}

func addressVersion(address netip.Addr, version uint8) bool {
	return address.IsValid() && (version == 4 && address.Is4() || version == 6 && address.Is6() && !address.Is4In6())
}

func validServiceVLAN(vlan uint16) bool {
	return vlan <= 4097 || vlan == math.MaxUint16
}

func (e *Engine) Join(request Join) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	e.expireLocked(now)

	subscriber, exists := e.config.subscribers[request.SubscriberID]
	if !exists {
		return Decision{Reason: ReasonUnknownSubscriber}
	}
	if !validJoin(request) {
		return Decision{Reason: ReasonUnauthorized}
	}
	state := e.subscriberStateLocked(request.SubscriberID)
	stream := streamKey{interfaceName: request.Interface, source: request.Source,
		group: request.Group, vlan: request.UNIVLAN}
	key := activeKey{interfaceName: request.Interface, source: request.Source,
		group: request.Group, vlan: request.UNIVLAN, client: request.Client}
	if active, exists := state.groups[key]; exists {
		active.joinedAt = now
		state.groups[key] = active
		state.joinMessages++
		return decisionFromActive(active, active.reason)
	}
	if active, exists := activeStream(state.groups, stream); exists {
		active.Client = request.Client
		active.joinedAt = now
		state.groups[key] = active
		state.joinMessages++
		return decisionFromActive(active, active.reason)
	}

	match, forward, forwardProfileID := e.matchLocked(subscriber, request, now)
	if match == nil {
		return Decision{ForwardUpstream: forward, Reason: ReasonUnauthorized,
			ProfileID: forwardProfileID}
	}

	groupExceeded := subscriber.MaxSimultaneousGroups != 0 &&
		activeStreamCount(state.groups, nil) >= int(subscriber.MaxSimultaneousGroups)
	bandwidth := activeBandwidth(state.groups, nil)
	bandwidthExceeded := exceedsBandwidth(bandwidth, match.acl.ImputedBandwidth,
		subscriber.MaxMulticastBandwidth)
	if match.service != nil {
		packageGroups := activePackageGroups(state.groups, match.service.RowKey)
		if match.service.MaxSimultaneousGroups != 0 &&
			packageGroups >= int(match.service.MaxSimultaneousGroups) {
			groupExceeded = true
		}
		packageBandwidth := activeBandwidth(state.groups, match.service)
		if exceedsBandwidth(packageBandwidth, match.acl.ImputedBandwidth,
			match.service.MaxMulticastBandwidth) {
			bandwidthExceeded = true
		}
	}
	if bandwidthExceeded {
		state.bandwidthExceeded++
	}
	if groupExceeded {
		return Decision{Reason: ReasonGroupLimit,
			BandwidthExceeded: bandwidthExceeded}
	}
	if bandwidthExceeded && subscriber.BandwidthEnforcement {
		return Decision{Reason: ReasonBandwidthExceeded,
			BandwidthExceeded: true}
	}
	if match.reason == ReasonPreview {
		previewDecision := e.startPreviewLocked(request.SubscriberID, match, request, now)
		if !previewDecision.Accepted {
			previewDecision.BandwidthExceeded = bandwidthExceeded
			return previewDecision
		}
		match.previewUntil = previewDecision.PreviewUntil
	}

	active := activeState{
		ActiveGroup: ActiveGroup{
			Interface: request.Interface, Source: request.Source, Group: request.Group, Client: request.Client,
			UNIVLAN: request.UNIVLAN, ANIVLAN: match.acl.VLANID,
			ProfileID: match.profile.EntityID, ACLRowKey: match.acl.RowKey,
			GEMPortID: match.acl.GEMPortID, ImputedBandwidth: match.acl.ImputedBandwidth,
			PreviewUntil: match.previewUntil,
		},
		joinedAt: now,
		reason:   match.reason,
	}
	if match.service != nil {
		active.packageID = match.service.RowKey
		active.hasPackage = true
	}
	state.groups[key] = active
	state.joinMessages++
	decision := decisionFromActive(active, match.reason)
	decision.BandwidthExceeded = bandwidthExceeded
	return decision
}

type policyMatch struct {
	profile      Profile
	acl          ACLEntry
	service      *ServicePackage
	reason       Reason
	previewUntil time.Time
}

func (e *Engine) matchLocked(subscriber compiledSubscriber, request Join,
	now time.Time) (*policyMatch, bool, uint16) {
	type candidate struct {
		profile Profile
		service *ServicePackage
	}
	candidates := make([]candidate, 0, max(1, len(subscriber.ServicePackages)))
	if len(subscriber.ServicePackages) == 0 {
		candidates = append(candidates, candidate{profile: e.config.profiles[subscriber.Profile]})
	} else {
		for index := range subscriber.ServicePackages {
			service := &subscriber.ServicePackages[index]
			if serviceVLANMatches(service.VLANID, request.UNIVLAN) {
				candidates = append(candidates, candidate{
					profile: e.config.profiles[service.OperationsProfile], service: service,
				})
			}
		}
	}
	forwardUnauthorized := false
	var forwardProfileID uint16
	previewMatches := make([]policyMatch, 0)
	for _, candidate := range candidates {
		if candidate.profile.UnauthorizedJoinBehaviour {
			forwardUnauthorized = true
			if forwardProfileID == 0 {
				forwardProfileID = candidate.profile.EntityID
			}
		}
		for _, acl := range candidate.profile.DynamicACL {
			if !aclMatches(acl, request.Source, request.Group) {
				continue
			}
			match := policyMatch{profile: candidate.profile, acl: acl, service: candidate.service}
			if acl.PreviewLength == 0 {
				match.reason = ReasonAuthorized
				return &match, true, match.profile.EntityID
			}
			previewMatches = append(previewMatches, match)
		}
	}
	for _, match := range previewMatches {
		for _, allowed := range subscriber.AllowedPreviews {
			expires := subscriber.previewExpiry[allowed.RowKey]
			if allowedPreviewMatches(allowed, expires,
				request, match.acl.VLANID, now) {
				match.reason = ReasonAllowedPreview
				match.previewUntil = expires
				return &match, true, match.profile.EntityID
			}
		}
	}
	if len(previewMatches) != 0 {
		previewMatches[0].reason = ReasonPreview
		return &previewMatches[0], true, previewMatches[0].profile.EntityID
	}
	return nil, forwardUnauthorized, forwardProfileID
}

func validJoin(request Join) bool {
	if !request.Group.IsValid() || !request.Group.IsMulticast() ||
		!request.Source.IsValid() || request.Source.BitLen() != request.Group.BitLen() ||
		request.UNIVLAN.ID > 4095 || !request.UNIVLAN.Tagged && request.UNIVLAN.ID != 0 {
		return false
	}
	return !request.Client.IsValid() || request.Client.BitLen() == request.Group.BitLen()
}

func aclMatches(acl ACLEntry, source, group netip.Addr) bool {
	if !addressVersion(group, acl.IPVersion) || group.Compare(acl.Start) < 0 || group.Compare(acl.Stop) > 0 {
		return false
	}
	return !acl.Source.IsValid() || acl.Source.IsUnspecified() || acl.Source == source
}

func serviceVLANMatches(policy uint16, packet VLAN) bool {
	switch policy {
	case 4096:
		return !packet.Tagged
	case 4097:
		return packet.Tagged
	case math.MaxUint16:
		return true
	default:
		return packet.Tagged && packet.ID == policy
	}
}

func allowedPreviewMatches(allowed AllowedPreview, expires time.Time, request Join,
	aniVLAN uint16, now time.Time) bool {
	if allowed.Duration != 0 && (allowed.TimeLeft == 0 || !expires.After(now)) {
		return false
	}
	if allowed.Destination != request.Group ||
		(allowed.Source.IsValid() && !allowed.Source.IsUnspecified() && allowed.Source != request.Source) {
		return false
	}
	if allowed.UNIVLAN == 0 {
		if request.UNIVLAN.Tagged {
			return false
		}
	} else if !request.UNIVLAN.Tagged || request.UNIVLAN.ID != allowed.UNIVLAN {
		return false
	}
	return aniVLAN == math.MaxUint16 || aniVLAN == 4097 && allowed.ANIVLAN != 0 || aniVLAN == allowed.ANIVLAN
}

func exceedsBandwidth(current uint64, additional, limit uint32) bool {
	return limit != 0 && uint64(additional) > uint64(limit) ||
		limit != 0 && current > uint64(limit)-uint64(additional)
}

func activeBandwidth(groups map[activeKey]activeState, service *ServicePackage) uint64 {
	var total uint64
	seen := make(map[streamKey]struct{}, len(groups))
	for _, group := range groups {
		if service != nil && (!group.hasPackage || group.packageID != service.RowKey) {
			continue
		}
		key := streamKey{interfaceName: group.Interface, source: group.Source,
			group: group.Group, vlan: group.UNIVLAN}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		total += uint64(group.ImputedBandwidth)
	}
	return total
}

func activePackageGroups(groups map[activeKey]activeState, row uint16) int {
	service := ServicePackage{RowKey: row}
	return activeStreamCount(groups, &service)
}

func activeStreamCount(groups map[activeKey]activeState, service *ServicePackage) int {
	seen := make(map[streamKey]struct{}, len(groups))
	for _, group := range groups {
		if service != nil && (!group.hasPackage || group.packageID != service.RowKey) {
			continue
		}
		seen[streamKey{interfaceName: group.Interface, source: group.Source,
			group: group.Group, vlan: group.UNIVLAN}] = struct{}{}
	}
	return len(seen)
}

func activeStream(groups map[activeKey]activeState, wanted streamKey) (activeState, bool) {
	for _, group := range groups {
		if group.Interface == wanted.interfaceName && group.Source == wanted.source &&
			group.Group == wanted.group && group.UNIVLAN == wanted.vlan {
			return group, true
		}
	}
	return activeState{}, false
}

func (e *Engine) startPreviewLocked(subscriberID uint16, match *policyMatch,
	request Join, now time.Time) Decision {
	key := previewKey{
		subscriber: subscriberID, profile: match.profile.EntityID, row: match.acl.RowKey,
		source: request.Source, group: request.Group,
	}
	state := e.previews[key]
	if match.acl.PreviewResetTime >= 1 && match.acl.PreviewResetTime <= 24 {
		boundary := latestReset(now, match.acl.PreviewResetTime)
		if state.lastReset.IsZero() {
			state.lastReset = boundary
		} else if boundary.After(state.lastReset) {
			state.count = 0
			state.nextAllowed = time.Time{}
			state.lastReset = boundary
		}
	}
	if now.Before(state.nextAllowed) {
		e.previews[key] = state
		return Decision{Reason: ReasonPreviewInterval,
			ProfileID: match.profile.EntityID, ACLRowKey: match.acl.RowKey}
	}
	if match.acl.PreviewRepeatCount != 0 && state.count >= match.acl.PreviewRepeatCount {
		e.previews[key] = state
		return Decision{Reason: ReasonPreviewExhausted,
			ProfileID: match.profile.EntityID, ACLRowKey: match.acl.RowKey}
	}
	state.count++
	length := time.Duration(match.acl.PreviewLength) * time.Second
	state.nextAllowed = now.Add(length + time.Duration(match.acl.PreviewRepeatTime)*time.Second)
	e.previews[key] = state
	return Decision{Accepted: true, ForwardUpstream: true, Replicate: true,
		Reason: ReasonPreview, ProfileID: match.profile.EntityID, ACLRowKey: match.acl.RowKey,
		GEMPortID: match.acl.GEMPortID, ANIVLAN: match.acl.VLANID,
		ImputedBandwidth: match.acl.ImputedBandwidth, PreviewUntil: now.Add(length)}
}

func latestReset(now time.Time, hour uint16) time.Time {
	resetHour := int(hour)
	if resetHour == 24 {
		resetHour = 0
	}
	boundary := time.Date(now.Year(), now.Month(), now.Day(), resetHour, 0, 0, 0, now.Location())
	if boundary.After(now) {
		boundary = boundary.AddDate(0, 0, -1)
	}
	return boundary
}

func decisionFromActive(active activeState, reason Reason) Decision {
	return Decision{
		Accepted: true, ForwardUpstream: true, Replicate: true, Reason: reason,
		ProfileID: active.ProfileID, ACLRowKey: active.ACLRowKey,
		GEMPortID: active.GEMPortID, ANIVLAN: active.ANIVLAN,
		ImputedBandwidth: active.ImputedBandwidth, PreviewUntil: active.PreviewUntil,
	}
}

func (e *Engine) subscriberStateLocked(entityID uint16) *subscriberState {
	state := e.state[entityID]
	if state == nil {
		state = &subscriberState{groups: make(map[activeKey]activeState)}
		e.state[entityID] = state
	}
	return state
}

func (e *Engine) Leave(request Join) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.state[request.SubscriberID]
	if state == nil {
		return false
	}
	key := activeKey{interfaceName: request.Interface, source: request.Source,
		group: request.Group, vlan: request.UNIVLAN, client: request.Client}
	if request.Client.IsValid() {
		if _, exists := state.groups[key]; !exists {
			return false
		}
		delete(state.groups, key)
		return true
	}
	removed := false
	for candidate := range state.groups {
		if candidate.interfaceName == request.Interface && candidate.source == request.Source &&
			candidate.group == request.Group && candidate.vlan == request.UNIVLAN {
			delete(state.groups, candidate)
			removed = true
		}
	}
	return removed
}

func (e *Engine) Expire() []ActiveGroup {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.expireLocked(e.now())
}

func (e *Engine) expireLocked(now time.Time) []ActiveGroup {
	var expired []ActiveGroup
	for _, state := range e.state {
		for key, group := range state.groups {
			if group.PreviewUntil.IsZero() || now.Before(group.PreviewUntil) {
				continue
			}
			expired = append(expired, group.ActiveGroup)
			delete(state.groups, key)
		}
	}
	return expired
}

func (e *Engine) Monitor(subscriberID uint16) Monitor {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	e.expireLocked(now)
	state := e.state[subscriberID]
	if state == nil {
		return Monitor{}
	}
	result := Monitor{
		JoinMessages: state.joinMessages, BandwidthExceeded: state.bandwidthExceeded,
		Groups: make([]ActiveGroup, 0, len(state.groups)),
	}
	var bandwidth uint64
	seen := make(map[streamKey]struct{}, len(state.groups))
	for _, group := range state.groups {
		value := group.ActiveGroup
		elapsed := now.Sub(group.joinedAt)
		if elapsed > time.Duration(math.MaxUint32)*time.Second {
			value.TimeSinceJoin = math.MaxUint32
		} else if elapsed > 0 {
			value.TimeSinceJoin = uint32(elapsed / time.Second)
		}
		key := streamKey{interfaceName: group.Interface, source: group.Source,
			group: group.Group, vlan: group.UNIVLAN}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			bandwidth += uint64(group.ImputedBandwidth)
		}
		result.Groups = append(result.Groups, value)
	}
	if bandwidth > math.MaxUint32 {
		result.CurrentBandwidth = math.MaxUint32
	} else {
		result.CurrentBandwidth = uint32(bandwidth)
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		if comparison := result.Groups[i].Group.Compare(result.Groups[j].Group); comparison != 0 {
			return comparison < 0
		}
		if comparison := result.Groups[i].Source.Compare(result.Groups[j].Source); comparison != 0 {
			return comparison < 0
		}
		return result.Groups[i].Client.Compare(result.Groups[j].Client) < 0
	})
	return result
}

// AllowedPreviewTimers returns every configured class-310 timer, including
// expired rows with a zero value. Keeping expired row keys visible lets omcid
// delete both row parts transactionally from its MIB and desired platform graph.
func (e *Engine) AllowedPreviewTimers(subscriberID uint16) []AllowedPreviewTimer {
	e.mu.Lock()
	defer e.mu.Unlock()

	subscriber, exists := e.config.subscribers[subscriberID]
	if !exists {
		return nil
	}
	now := e.now()
	result := make([]AllowedPreviewTimer, 0, len(subscriber.AllowedPreviews))
	for _, preview := range subscriber.AllowedPreviews {
		timer := AllowedPreviewTimer{RowKey: preview.RowKey, Duration: preview.Duration}
		if deadline, timed := subscriber.previewExpiry[preview.RowKey]; timed && deadline.After(now) {
			remaining := deadline.Sub(now)
			minutes := (remaining + time.Minute - 1) / time.Minute
			if minutes > time.Duration(math.MaxUint16) {
				timer.TimeLeft = math.MaxUint16
			} else {
				timer.TimeLeft = uint16(minutes)
			}
		}
		result = append(result, timer)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RowKey < result[j].RowKey })
	return result
}

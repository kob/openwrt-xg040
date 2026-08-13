// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	multicastDownstreamChain = 2013
	multicastGEMChainBase    = 20000
	normalDownstreamChain    = 2012
	proxyQueryMark           = 0xa17f0001
	gponGEMMarkKey           = 0xa1700000
)

type CommandRunner interface {
	Run(name string, arguments ...string) error
}

type OutputCommandRunner interface {
	Output(name string, arguments ...string) ([]byte, error)
}

type ExecCommandRunner struct {
	Timeout time.Duration
}

func (r ExecCommandRunner) Run(name string, arguments ...string) error {
	_, err := r.Output(name, arguments...)
	return err
}

func (r ExecCommandRunner) Output(name string, arguments ...string) ([]byte, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out: %w", name, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("%s %v: %w: %s", name, arguments, err, output)
	}
	return output, nil
}

type LinuxBackendOptions struct {
	TC           string
	Runner       CommandRunner
	Sender       func(string, []byte) error
	MarkedSender func(string, []byte, uint32) error
	QuerySender  func(string, []byte) error
	PON          string
	Now          func() time.Time
}

type LinuxBackend struct {
	mu sync.Mutex

	tc           string
	runner       CommandRunner
	output       OutputCommandRunner
	sender       func(string, []byte) error
	markedSender func(string, []byte, uint32) error
	querySender  func(string, []byte) error
	pon          string
	control      map[string][]downstreamRule
	static       map[string][]downstreamRule
	dynamic      map[dynamicRuleKey]downstreamRule
	filters      map[dynamicRuleKey][]tcFilterRef
	baselines    map[dynamicRuleKey]bandwidthBaseline
	chains       map[string]map[uint16]struct{}
	now          func() time.Time
}

type downstreamRule struct {
	interfaceName string
	aniVLAN       uint16
	gemPortID     uint16
	uniVLAN       VLAN
	source        netip.Addr
	excluded      []netip.Addr
	start         netip.Addr
	stop          netip.Addr
	profile       Profile
}

type installedDownstreamRule struct {
	rule       downstreamRule
	dynamicKey *dynamicRuleKey
}

type dynamicRuleKey struct {
	subscriberID  uint16
	interfaceName string
	source        netip.Addr
	group         netip.Addr
	uniVLAN       VLAN
}

type tcFilterRef struct {
	interfaceName string
	chain         int
	preference    int
}

type bandwidthBaseline struct {
	bytes uint64
	at    time.Time
}

func NewLinuxBackend(options LinuxBackendOptions) *LinuxBackend {
	if options.TC == "" {
		options.TC = "/sbin/tc"
	}
	if options.Runner == nil {
		options.Runner = ExecCommandRunner{}
	}
	output, _ := options.Runner.(OutputCommandRunner)
	if options.Sender == nil {
		options.Sender = sendEthernetFrame
	}
	if options.MarkedSender == nil {
		options.MarkedSender = sendEthernetFrameMarked
	}
	if options.QuerySender == nil {
		options.QuerySender = func(interfaceName string, frame []byte) error {
			return sendEthernetFrameMarked(interfaceName, frame, proxyQueryMark)
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.PON == "" {
		options.PON = "pon"
	}
	return &LinuxBackend{tc: options.TC, runner: options.Runner, sender: options.Sender,
		output: output, markedSender: options.MarkedSender, querySender: options.QuerySender,
		pon: options.PON, now: options.Now,
		control: make(map[string][]downstreamRule), static: make(map[string][]downstreamRule),
		dynamic: make(map[dynamicRuleKey]downstreamRule),
		filters: make(map[dynamicRuleKey][]tcFilterRef), baselines: make(map[dynamicRuleKey]bandwidthBaseline),
		chains: make(map[string]map[uint16]struct{})}
}

func (b *LinuxBackend) Configure(config Config) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	profiles := make(map[uint16]Profile, len(config.Profiles))
	for _, profile := range config.Profiles {
		if err := validateDownstreamProfile(profile); err != nil {
			return err
		}
		profiles[profile.EntityID] = profile
	}
	candidate := make(map[string][]downstreamRule)
	candidateControl := make(map[string][]downstreamRule)
	for _, subscriber := range config.Subscribers {
		for _, attachment := range subscriber.Attachments {
			if attachment.BridgeEntity == 0 && attachment.DirectMapper == nil {
				return fmt.Errorf("multicast subscriber %#x attachment %s has no ANI bridge endpoint",
					subscriber.EntityID, attachment.Interface)
			}
			if attachment.BridgeEntity != 0 && attachment.DirectMapper != nil {
				return fmt.Errorf("multicast subscriber %#x attachment %s has both bridge and direct mapper paths",
					subscriber.EntityID, attachment.Interface)
			}
			if attachment.DirectMapper != nil {
				if err := validateUpstreamMapper(attachment.DirectMapper); err != nil {
					return fmt.Errorf("multicast subscriber %#x attachment %s: %w",
						subscriber.EntityID, attachment.Interface, err)
				}
			}
			if len(subscriber.ServicePackages) == 0 {
				profile := profiles[subscriber.Profile]
				candidateControl[attachment.Interface] = append(candidateControl[attachment.Interface],
					controlDownstreamRules(attachment.Interface, VLAN{}, profile)...)
				candidate[attachment.Interface] = append(candidate[attachment.Interface],
					staticDownstreamRules(attachment.Interface, VLAN{}, profile)...)
				continue
			}
			for _, service := range subscriber.ServicePackages {
				profile := profiles[service.OperationsProfile]
				uniVLAN := servicePacketVLAN(service.VLANID)
				candidateControl[attachment.Interface] = append(candidateControl[attachment.Interface],
					controlDownstreamRules(attachment.Interface, uniVLAN, profile)...)
				candidate[attachment.Interface] = append(candidate[attachment.Interface],
					staticDownstreamRules(attachment.Interface, uniVLAN, profile)...)
			}
		}
	}
	interfaces := make(map[string]struct{}, len(b.static)+len(candidate)+len(b.control)+len(candidateControl))
	for interfaceName := range b.control {
		interfaces[interfaceName] = struct{}{}
	}
	for interfaceName := range b.static {
		interfaces[interfaceName] = struct{}{}
	}
	for interfaceName := range candidate {
		interfaces[interfaceName] = struct{}{}
	}
	for interfaceName := range candidateControl {
		interfaces[interfaceName] = struct{}{}
	}
	previousControl := b.control
	previousStatic := b.static
	previousDynamic := b.dynamic
	b.control = candidateControl
	b.static = candidate
	b.dynamic = make(map[dynamicRuleKey]downstreamRule)
	for interfaceName := range interfaces {
		if err := b.rebuildLocked(interfaceName); err != nil {
			b.control = previousControl
			b.static = previousStatic
			b.dynamic = previousDynamic
			for rollbackInterface := range interfaces {
				_ = b.rebuildLocked(rollbackInterface)
			}
			return fmt.Errorf("configure multicast filters on %s: %w", interfaceName, err)
		}
	}
	return nil
}

func validateUpstreamMapper(mapper *UpstreamMapper) error {
	if mapper == nil || mapper.UnmarkedFrameOption > 1 || mapper.DefaultPBit > 7 {
		return fmt.Errorf("invalid direct mapper policy")
	}
	for priority, gemPortID := range mapper.GEMPortIDs {
		if gemPortID > 4095 && gemPortID != math.MaxUint16 {
			return fmt.Errorf("direct mapper P-bit %d has invalid GEM %d", priority, gemPortID)
		}
	}
	for dscp, priority := range mapper.DSCPToPBit {
		if priority > 7 {
			return fmt.Errorf("direct mapper DSCP %d has invalid P-bit %d", dscp, priority)
		}
	}
	return nil
}

func validateDownstreamProfile(profile Profile) error {
	if profile.DownstreamTagControl > 7 {
		return fmt.Errorf("multicast profile %#x has invalid downstream tag control %d",
			profile.EntityID, profile.DownstreamTagControl)
	}
	return nil
}

func staticDownstreamRules(interfaceName string, uniVLAN VLAN, profile Profile) []downstreamRule {
	result := make([]downstreamRule, 0, len(profile.StaticACL))
	for _, entry := range profile.StaticACL {
		result = append(result, downstreamRule{interfaceName: interfaceName,
			aniVLAN: entry.VLANID, gemPortID: entry.GEMPortID, uniVLAN: uniVLAN, source: entry.Source,
			start: entry.Start, stop: entry.Stop, profile: profile})
	}
	return result
}

func controlDownstreamRules(interfaceName string, uniVLAN VLAN, profile Profile) []downstreamRule {
	type controlKey struct {
		gem  uint16
		vlan uint16
	}
	seen := make(map[controlKey]struct{})
	result := make([]downstreamRule, 0)
	for _, entries := range [][]ACLEntry{profile.DynamicACL, profile.StaticACL} {
		for _, entry := range entries {
			key := controlKey{gem: entry.GEMPortID, vlan: entry.VLANID}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, downstreamRule{interfaceName: interfaceName,
				aniVLAN: entry.VLANID, gemPortID: entry.GEMPortID, uniVLAN: uniVLAN, profile: profile})
		}
	}
	return result
}

func servicePacketVLAN(value uint16) VLAN {
	switch value {
	case 4096, math.MaxUint16:
		return VLAN{}
	case 4097:
		return VLAN{Tagged: true}
	default:
		return VLAN{Tagged: true, ID: value}
	}
}

func (b *LinuxBackend) SetReplication(change ReplicationChange) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := dynamicRuleKey{subscriberID: change.Subscriber.EntityID,
		interfaceName: change.Attachment.Interface, source: change.Group.Source,
		group: change.Group.Group, uniVLAN: change.Group.UNIVLAN}
	previous, existed := b.dynamic[key]
	if change.Enable {
		b.dynamic[key] = downstreamRule{interfaceName: change.Attachment.Interface,
			aniVLAN: change.Group.ANIVLAN, gemPortID: change.Group.GEMPortID,
			uniVLAN: change.Group.UNIVLAN, excluded: cloneAddresses(change.Group.ExcludedSources),
			source: change.Group.Source, start: change.Group.Group, stop: change.Group.Group,
			profile: change.Profile}
	} else {
		delete(b.dynamic, key)
	}
	if err := b.rebuildLocked(change.Attachment.Interface); err != nil {
		if existed {
			b.dynamic[key] = previous
		} else {
			delete(b.dynamic, key)
		}
		_ = b.rebuildLocked(change.Attachment.Interface)
		return err
	}
	return nil
}

func (b *LinuxBackend) SendReport(report UpstreamReport) error {
	frame, err := BuildUpstreamFrame(report)
	if err != nil || frame == nil {
		return err
	}
	if report.Attachment.BridgeEntity == 0 {
		if report.Attachment.DirectMapper == nil {
			return fmt.Errorf("multicast attachment %s has no ANI bridge endpoint or direct mapper",
				report.Attachment.Interface)
		}
		gemPortID, err := directMapperGEM(report.Attachment.DirectMapper, frame)
		if err != nil {
			return fmt.Errorf("select upstream multicast report GEM on %s: %w",
				report.Attachment.Interface, err)
		}
		mark := uint32(gponGEMMarkKey | uint32(gemPortID))
		if err := b.markedSender(b.pon, frame, mark); err != nil {
			return fmt.Errorf("send report on %s GEM %d: %w", b.pon, gemPortID, err)
		}
		return nil
	}
	ani := fmt.Sprintf("oma%04x", report.Attachment.BridgeEntity)
	if err := b.sender(ani, frame); err != nil {
		return fmt.Errorf("send report on %s: %w", ani, err)
	}
	return nil
}

func directMapperGEM(mapper *UpstreamMapper, frame []byte) (uint16, error) {
	if mapper == nil || mapper.UnmarkedFrameOption > 1 || mapper.DefaultPBit > 7 {
		return 0, fmt.Errorf("invalid direct mapper policy")
	}
	if len(frame) < 14 {
		return 0, fmt.Errorf("short Ethernet frame")
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	var priority uint8
	if etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100 {
		if len(frame) < 18 {
			return 0, fmt.Errorf("short tagged Ethernet frame")
		}
		priority = uint8(binary.BigEndian.Uint16(frame[14:16]) >> 13)
	} else if mapper.UnmarkedFrameOption == 1 {
		priority = mapper.DefaultPBit
	} else {
		var dscp uint8
		switch etherType {
		case 0x0800:
			if len(frame) < offset+2 {
				return 0, fmt.Errorf("short IPv4 frame")
			}
			dscp = frame[offset+1] >> 2
		case 0x86dd:
			if len(frame) < offset+2 {
				return 0, fmt.Errorf("short IPv6 frame")
			}
			trafficClass := (frame[offset]&0x0f)<<4 | frame[offset+1]>>4
			dscp = trafficClass >> 2
		default:
			priority = 0
		}
		if etherType == 0x0800 || etherType == 0x86dd {
			priority = mapper.DSCPToPBit[dscp]
		}
	}
	if priority > 7 {
		return 0, fmt.Errorf("mapper selected invalid P-bit %d", priority)
	}
	gemPortID := mapper.GEMPortIDs[priority]
	if gemPortID > 4095 {
		return 0, fmt.Errorf("P-bit %d has no upstream GEM", priority)
	}
	return gemPortID, nil
}

func (b *LinuxBackend) SendQuery(query DownstreamQuery) error {
	device, err := net.InterfaceByName(query.Attachment.Interface)
	if err != nil {
		return fmt.Errorf("resolve query interface %s: %w", query.Attachment.Interface, err)
	}
	if len(device.HardwareAddr) != 6 {
		return fmt.Errorf("query interface %s has invalid hardware address", query.Attachment.Interface)
	}
	var sourceMAC [6]byte
	copy(sourceMAC[:], device.HardwareAddr)
	frame, err := BuildDownstreamQueryFrame(query, sourceMAC)
	if err != nil {
		return err
	}
	if err := b.querySender(query.Attachment.Interface, frame); err != nil {
		return fmt.Errorf("send query on %s: %w", query.Attachment.Interface, err)
	}
	return nil
}

func (b *LinuxBackend) rebuildLocked(interfaceName string) error {
	desiredGEMs := make(map[uint16]struct{})
	for _, rule := range b.control[interfaceName] {
		desiredGEMs[rule.gemPortID] = struct{}{}
	}
	for _, rule := range b.static[interfaceName] {
		desiredGEMs[rule.gemPortID] = struct{}{}
	}
	for key, rule := range b.dynamic {
		if key.interfaceName == interfaceName {
			desiredGEMs[rule.gemPortID] = struct{}{}
		}
	}
	touchedGEMs := make(map[uint16]struct{}, len(desiredGEMs)+len(b.chains[interfaceName]))
	for gem := range desiredGEMs {
		touchedGEMs[gem] = struct{}{}
	}
	for gem := range b.chains[interfaceName] {
		touchedGEMs[gem] = struct{}{}
	}
	// Retain the attempted set until a complete rebuild succeeds so rollback
	// can remove child chains created by a partially failed transaction.
	b.chains[interfaceName] = touchedGEMs
	// Deleting a missing chain is expected on first configuration.
	_ = b.runner.Run(b.tc, "filter", "del", "dev", interfaceName, "egress",
		"chain", strconv.Itoa(multicastDownstreamChain))
	for gem := range touchedGEMs {
		_ = b.runner.Run(b.tc, "filter", "del", "dev", interfaceName, "egress",
			"chain", strconv.Itoa(multicastGEMChain(gem)))
	}
	if err := b.runner.Run(b.tc, "filter", "replace", "dev", interfaceName, "egress",
		"chain", strconv.Itoa(multicastDownstreamChain), "protocol", "all", "pref", "1",
		"handle", fmt.Sprintf("%#x", proxyQueryMark), "fw", "action", "pass"); err != nil {
		return err
	}
	gems := make([]int, 0, len(desiredGEMs))
	for gem := range desiredGEMs {
		gems = append(gems, int(gem))
	}
	sort.Ints(gems)
	for _, gem := range gems {
		if err := b.runner.Run(b.tc, "filter", "replace", "dev", interfaceName, "egress",
			"chain", strconv.Itoa(multicastDownstreamChain), "protocol", "all",
			"pref", strconv.Itoa(100+gem), "handle",
			fmt.Sprintf("%#x/0xffffffff", gponGEMMarkKey|gem), "fw", "action", "goto",
			"chain", strconv.Itoa(multicastGEMChain(uint16(gem)))); err != nil {
			return err
		}
	}
	control := append([]downstreamRule(nil), b.control[interfaceName]...)
	sort.Slice(control, func(i, j int) bool {
		if control[i].gemPortID != control[j].gemPortID {
			return control[i].gemPortID < control[j].gemPortID
		}
		if control[i].profile.EntityID != control[j].profile.EntityID {
			return control[i].profile.EntityID < control[j].profile.EntityID
		}
		if control[i].aniVLAN != control[j].aniVLAN {
			return control[i].aniVLAN < control[j].aniVLAN
		}
		return control[i].uniVLAN.ID < control[j].uniVLAN.ID
	})
	preferenceByGEM := make(map[uint16]int)
	for _, rule := range control {
		preference := preferenceByGEM[rule.gemPortID]
		if preference == 0 {
			preference = 10
		}
		ipv4 := rule.profile.IGMPVersion <= 3
		for _, variant := range downstreamVariants(rule.aniVLAN, ipv4) {
			arguments, err := downstreamControlFilterArguments(interfaceName, preference, rule, variant)
			if err != nil {
				return err
			}
			if err := b.runner.Run(b.tc, arguments...); err != nil {
				return err
			}
			preference++
			if preference >= 1000 {
				return fmt.Errorf("multicast control filter count exceeds reserved tc preference space")
			}
		}
		preferenceByGEM[rule.gemPortID] = preference
	}

	// Active exact-match rules precede static ranges. Besides making their byte
	// counters observable, this prevents a broad static ACL from consuming a
	// packet before the per-stream class-311 accounting rule sees it.
	rules := make([]installedDownstreamRule, 0, len(b.dynamic)+len(b.static[interfaceName]))
	for key, rule := range b.dynamic {
		if key.interfaceName == interfaceName {
			keyCopy := key
			rules = append(rules, installedDownstreamRule{rule: rule, dynamicKey: &keyCopy})
		}
	}
	for _, rule := range b.static[interfaceName] {
		rules = append(rules, installedDownstreamRule{rule: rule})
	}
	sort.Slice(rules, func(i, j int) bool {
		if (rules[i].dynamicKey != nil) != (rules[j].dynamicKey != nil) {
			return rules[i].dynamicKey != nil
		}
		if comparison := rules[i].rule.start.Compare(rules[j].rule.start); comparison != 0 {
			return comparison < 0
		}
		leftSpecific := rules[i].rule.source.IsValid() && !rules[i].rule.source.IsUnspecified()
		rightSpecific := rules[j].rule.source.IsValid() && !rules[j].rule.source.IsUnspecified()
		if leftSpecific != rightSpecific {
			return leftSpecific
		}
		if comparison := rules[i].rule.source.Compare(rules[j].rule.source); comparison != 0 {
			return comparison < 0
		}
		if rules[i].rule.profile.EntityID != rules[j].rule.profile.EntityID {
			return rules[i].rule.profile.EntityID < rules[j].rule.profile.EntityID
		}
		if rules[i].dynamicKey != nil && rules[j].dynamicKey != nil {
			return dynamicRuleKeyLess(*rules[i].dynamicKey, *rules[j].dynamicKey)
		}
		return false
	})
	preferenceByGEM = make(map[uint16]int)
	installedFilters := make(map[dynamicRuleKey][]tcFilterRef)
	for _, installed := range rules {
		rule := installed.rule
		preference := preferenceByGEM[rule.gemPortID]
		if preference == 0 {
			preference = 1000
		}
		prefixes, err := addressRangePrefixes(rule.start, rule.stop)
		if err != nil {
			return err
		}
		for _, prefix := range prefixes {
			variants := downstreamVariants(rule.aniVLAN, prefix.Addr().Is4())
			for _, variant := range variants {
				excludedSources := rule.excluded
				if installed.dynamicKey != nil {
					excludedSources = b.effectiveExcludedSources(*installed.dynamicKey, rule)
				}
				for _, excluded := range excludedSources {
					arguments, err := downstreamExcludeFilterArguments(interfaceName, preference,
						rule, prefix, variant, excluded)
					if err != nil {
						return err
					}
					if err := b.runner.Run(b.tc, arguments...); err != nil {
						return err
					}
					preference++
				}
				arguments, err := downstreamFilterArguments(interfaceName, preference,
					rule, prefix, variant)
				if err != nil {
					return err
				}
				if err := b.runner.Run(b.tc, arguments...); err != nil {
					return err
				}
				if installed.dynamicKey != nil {
					installedFilters[*installed.dynamicKey] = append(installedFilters[*installed.dynamicKey],
						tcFilterRef{interfaceName: interfaceName,
							chain: multicastGEMChain(rule.gemPortID), preference: preference})
				}
				preference++
				if preference >= 64000 {
					return fmt.Errorf("multicast filter count exceeds tc preference space")
				}
			}
		}
		preferenceByGEM[rule.gemPortID] = preference
	}
	for _, gem := range gems {
		if err := b.runner.Run(b.tc, "filter", "replace", "dev", interfaceName, "egress",
			"chain", strconv.Itoa(multicastGEMChain(uint16(gem))), "protocol", "all", "pref", "65000",
			"flower", "skip_hw", "action", "drop"); err != nil {
			return err
		}
	}
	if err := b.runner.Run(b.tc, "filter", "replace", "dev", interfaceName, "egress",
		"chain", strconv.Itoa(multicastDownstreamChain), "protocol", "all", "pref", "65000",
		"flower", "skip_hw", "action", "drop"); err != nil {
		return err
	}
	for key := range b.filters {
		if key.interfaceName == interfaceName {
			delete(b.filters, key)
		}
	}
	for key := range b.baselines {
		if key.interfaceName == interfaceName {
			delete(b.baselines, key)
		}
	}
	for key, references := range installedFilters {
		b.filters[key] = references
	}
	b.chains[interfaceName] = desiredGEMs
	return nil
}

func (b *LinuxBackend) effectiveExcludedSources(key dynamicRuleKey, rule downstreamRule) []netip.Addr {
	if !key.source.IsUnspecified() || len(rule.excluded) == 0 {
		return rule.excluded
	}
	result := make([]netip.Addr, 0, len(rule.excluded))
	for _, excluded := range rule.excluded {
		included := dynamicRuleKey{subscriberID: key.subscriberID, interfaceName: key.interfaceName,
			source: excluded, group: key.group, uniVLAN: key.uniVLAN}
		includedRule, exists := b.dynamic[included]
		if !exists || includedRule.gemPortID != rule.gemPortID {
			result = append(result, excluded)
		}
	}
	return result
}

func multicastGEMChain(gemPortID uint16) int {
	return multicastGEMChainBase + int(gemPortID)
}

func dynamicRuleKeyLess(left, right dynamicRuleKey) bool {
	if left.subscriberID != right.subscriberID {
		return left.subscriberID < right.subscriberID
	}
	if comparison := left.group.Compare(right.group); comparison != 0 {
		return comparison < 0
	}
	if comparison := left.source.Compare(right.source); comparison != 0 {
		return comparison < 0
	}
	if left.uniVLAN.Tagged != right.uniVLAN.Tagged {
		return !left.uniVLAN.Tagged
	}
	return left.uniVLAN.ID < right.uniVLAN.ID
}

// SampleBandwidth reads the byte counters of the exact-match rules installed
// for active streams. Multiple VLAN protocol/tag variants are summed before a
// byte-per-second rate is derived. The first read after every chain rebuild is
// a baseline and intentionally produces no sample.
func (b *LinuxBackend) SampleBandwidth() (map[BandwidthKey]uint32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make(map[BandwidthKey]uint32)
	if b.output == nil || len(b.filters) == 0 {
		return result, nil
	}
	type counterChain struct {
		interfaceName string
		chain         int
	}
	chains := make(map[counterChain]struct{})
	for _, references := range b.filters {
		for _, reference := range references {
			chains[counterChain{interfaceName: reference.interfaceName, chain: reference.chain}] = struct{}{}
		}
	}
	keys := make([]counterChain, 0, len(chains))
	for key := range chains {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].interfaceName != keys[j].interfaceName {
			return keys[i].interfaceName < keys[j].interfaceName
		}
		return keys[i].chain < keys[j].chain
	})
	counters := make(map[counterChain]map[int]uint64, len(keys))
	for _, key := range keys {
		output, err := b.output.Output(b.tc, "-j", "-s", "filter", "show", "dev",
			key.interfaceName, "egress", "chain", strconv.Itoa(key.chain))
		if err != nil {
			return nil, fmt.Errorf("read multicast filter counters on %s chain %d: %w",
				key.interfaceName, key.chain, err)
		}
		parsed, err := tcFilterByteCounters(output)
		if err != nil {
			return nil, fmt.Errorf("decode multicast filter counters on %s chain %d: %w",
				key.interfaceName, key.chain, err)
		}
		counters[key] = parsed
	}
	now := b.now()
	for key, references := range b.filters {
		var total uint64
		for _, reference := range references {
			value, exists := counters[counterChain{interfaceName: reference.interfaceName,
				chain: reference.chain}][reference.preference]
			if !exists {
				return nil, fmt.Errorf("multicast filter preference %d is missing on %s",
					reference.preference, reference.interfaceName)
			}
			if math.MaxUint64-total < value {
				total = math.MaxUint64
			} else {
				total += value
			}
		}
		previous, exists := b.baselines[key]
		if !exists || total < previous.bytes {
			b.baselines[key] = bandwidthBaseline{bytes: total, at: now}
			continue
		}
		if !now.After(previous.at) {
			continue
		}
		seconds := now.Sub(previous.at).Seconds()
		rate := float64(total-previous.bytes) / seconds
		var value uint32
		if rate >= float64(math.MaxUint32) {
			value = math.MaxUint32
		} else {
			value = uint32(rate)
		}
		result[BandwidthKey{SubscriberID: key.subscriberID, Interface: key.interfaceName,
			Source: key.source, Group: key.group, UNIVLAN: key.uniVLAN}] = value
		b.baselines[key] = bandwidthBaseline{bytes: total, at: now}
	}
	return result, nil
}

func tcFilterByteCounters(document []byte) (map[int]uint64, error) {
	type action struct {
		Stats *struct {
			Bytes *uint64 `json:"bytes"`
		} `json:"stats"`
	}
	type filter struct {
		Preference json.RawMessage `json:"pref"`
		Options    struct {
			Actions []action `json:"actions"`
		} `json:"options"`
	}
	var filters []filter
	if err := json.Unmarshal(document, &filters); err != nil {
		return nil, err
	}
	result := make(map[int]uint64, len(filters))
	for _, filter := range filters {
		preference, err := tcPreference(filter.Preference)
		if err != nil {
			return nil, err
		}
		var bytes *uint64
		for _, candidate := range filter.Options.Actions {
			if candidate.Stats != nil && candidate.Stats.Bytes != nil {
				bytes = candidate.Stats.Bytes
				break
			}
		}
		if bytes == nil {
			// iproute2 emits a short protocol/preference header immediately
			// before the detailed filter object. Only the latter owns stats.
			continue
		}
		if math.MaxUint64-result[preference] < *bytes {
			result[preference] = math.MaxUint64
		} else {
			result[preference] += *bytes
		}
	}
	return result, nil
}

func tcPreference(value json.RawMessage) (int, error) {
	var numeric uint32
	if err := json.Unmarshal(value, &numeric); err == nil {
		return int(numeric), nil
	}
	var text string
	if err := json.Unmarshal(value, &text); err == nil {
		parsed, parseErr := strconv.ParseUint(text, 0, 32)
		if parseErr == nil {
			return int(parsed), nil
		}
	}
	return 0, fmt.Errorf("filter has invalid preference %s", value)
}

func downstreamControlFilterArguments(interfaceName string, preference int, rule downstreamRule,
	variant downstreamVariant) ([]string, error) {
	arguments := []string{"filter", "replace", "dev", interfaceName, "egress", "chain",
		strconv.Itoa(multicastGEMChain(rule.gemPortID)), "protocol", variant.protocol,
		"pref", strconv.Itoa(preference), "flower", "skip_hw"}
	if variant.tagged {
		arguments = append(arguments, "num_of_vlans", strconv.Itoa(variant.tags))
		if rule.aniVLAN <= 4095 {
			arguments = append(arguments, "vlan_id", strconv.Itoa(int(rule.aniVLAN)))
		}
		encapsulated := "vlan_ethtype"
		if variant.tags == 2 {
			encapsulated = "cvlan_ethtype"
		}
		if rule.profile.IGMPVersion <= 3 {
			arguments = append(arguments, encapsulated, "ip")
		} else {
			arguments = append(arguments, encapsulated, "ipv6")
		}
	}
	if rule.profile.IGMPVersion <= 3 {
		arguments = append(arguments, "ip_proto", "2")
	} else {
		arguments = append(arguments, "ip_proto", "icmpv6", "type", "130")
	}
	actions, err := downstreamActions(rule.profile, rule.uniVLAN, variant.tagged)
	if err != nil {
		return nil, err
	}
	return append(arguments, actions...), nil
}

type downstreamVariant struct {
	protocol string
	tagged   bool
	tags     int
}

func downstreamVariants(aniVLAN uint16, ipv4 bool) []downstreamVariant {
	untaggedProtocol := "ipv6"
	if ipv4 {
		untaggedProtocol = "ip"
	}
	untagged := downstreamVariant{protocol: untaggedProtocol}
	var tagged []downstreamVariant
	for _, protocol := range []string{"802.1Q", "802.1ad"} {
		for count := 1; count <= 2; count++ {
			tagged = append(tagged, downstreamVariant{protocol: protocol, tagged: true, tags: count})
		}
	}
	switch aniVLAN {
	case 0:
		return []downstreamVariant{untagged}
	case 4097:
		return tagged
	case math.MaxUint16:
		return append([]downstreamVariant{untagged}, tagged...)
	default:
		return tagged
	}
}

func downstreamFilterArguments(interfaceName string, preference int, rule downstreamRule,
	prefix netip.Prefix, variant downstreamVariant) ([]string, error) {
	arguments := []string{"filter", "replace", "dev", interfaceName, "egress", "chain",
		strconv.Itoa(multicastGEMChain(rule.gemPortID)), "protocol", variant.protocol,
		"pref", strconv.Itoa(preference), "flower", "skip_hw"}
	if variant.tagged {
		arguments = append(arguments, "num_of_vlans", strconv.Itoa(variant.tags))
		if rule.aniVLAN <= 4095 {
			arguments = append(arguments, "vlan_id", strconv.Itoa(int(rule.aniVLAN)))
		}
		encapsulated := "vlan_ethtype"
		if variant.tags == 2 {
			encapsulated = "cvlan_ethtype"
		}
		if prefix.Addr().Is4() {
			arguments = append(arguments, encapsulated, "ip")
		} else {
			arguments = append(arguments, encapsulated, "ipv6")
		}
	}
	if rule.source.IsValid() && !rule.source.IsUnspecified() {
		arguments = append(arguments, "src_ip", rule.source.String())
	}
	arguments = append(arguments, "dst_ip", prefix.String())
	actions, err := downstreamActions(rule.profile, rule.uniVLAN, variant.tagged)
	if err != nil {
		return nil, err
	}
	return append(arguments, actions...), nil
}

func downstreamExcludeFilterArguments(interfaceName string, preference int, rule downstreamRule,
	prefix netip.Prefix, variant downstreamVariant, source netip.Addr) ([]string, error) {
	if !source.IsValid() || source.BitLen() != prefix.Addr().BitLen() {
		return nil, fmt.Errorf("multicast exclusion source %s does not match group %s", source, prefix)
	}
	arguments := []string{"filter", "replace", "dev", interfaceName, "egress", "chain",
		strconv.Itoa(multicastGEMChain(rule.gemPortID)), "protocol", variant.protocol,
		"pref", strconv.Itoa(preference), "flower", "skip_hw"}
	if variant.tagged {
		arguments = append(arguments, "num_of_vlans", strconv.Itoa(variant.tags))
		if rule.aniVLAN <= 4095 {
			arguments = append(arguments, "vlan_id", strconv.Itoa(int(rule.aniVLAN)))
		}
		encapsulated := "vlan_ethtype"
		if variant.tags == 2 {
			encapsulated = "cvlan_ethtype"
		}
		if prefix.Addr().Is4() {
			arguments = append(arguments, encapsulated, "ip")
		} else {
			arguments = append(arguments, encapsulated, "ipv6")
		}
	}
	return append(arguments, "src_ip", source.String(), "dst_ip", prefix.String(), "action", "drop"), nil
}

func downstreamActions(profile Profile, uniVLAN VLAN, tagged bool) ([]string, error) {
	control := profile.DownstreamTagControl
	tci := profile.DownstreamTCI
	if control >= 5 {
		if uniVLAN.Tagged && uniVLAN.ID <= 4094 {
			tci = tci&0xf000 | uniVLAN.ID
		} else if control == 6 || control == 7 {
			if !uniVLAN.Tagged {
				if tagged {
					return []string{"action", "vlan", "pop", "pipe", "action", "pass"}, nil
				}
				return []string{"action", "pass"}, nil
			}
		}
	}
	vid := strconv.Itoa(int(tci & 0x0fff))
	priority := strconv.Itoa(int(tci >> 13 & 7))
	dei := strconv.Itoa(int(tci >> 12 & 1))
	push := []string{"action", "vlan", "push", "protocol", "802.1Q", "id", vid,
		"priority", priority, "dei", dei, "pipe", "action", "pass"}
	modify := []string{"action", "vlan", "modify", "id", vid,
		"priority", priority, "dei", dei, "pipe", "action", "pass"}
	pushVID := []string{"action", "vlan", "push", "protocol", "802.1Q", "id", vid,
		"pipe", "action", "pass"}
	switch control {
	case 0:
		return []string{"action", "goto", "chain", strconv.Itoa(normalDownstreamChain)}, nil
	case 1:
		if tagged {
			return []string{"action", "vlan", "pop", "pipe", "action", "pass"}, nil
		}
		return []string{"action", "pass"}, nil
	case 2, 5:
		return push, nil
	case 3, 6:
		if tagged {
			return modify, nil
		}
		return push, nil
	case 4, 7:
		if tagged {
			return []string{"action", "vlan", "modify", "id", vid, "pipe", "action", "pass"}, nil
		}
		return pushVID, nil
	default:
		return nil, fmt.Errorf("invalid downstream multicast tag control %d", control)
	}
}

func addressRangePrefixes(start, stop netip.Addr) ([]netip.Prefix, error) {
	if !start.IsValid() || !stop.IsValid() || start.BitLen() != stop.BitLen() || start.Compare(stop) > 0 {
		return nil, fmt.Errorf("invalid multicast range %s..%s", start, stop)
	}
	if start.Is4() {
		return ipv4RangePrefixes(start, stop), nil
	}
	return ipv6RangePrefixes(start, stop), nil
}

func ipv4RangePrefixes(start, stop netip.Addr) []netip.Prefix {
	current := binaryAddress4(start)
	last := binaryAddress4(stop)
	var result []netip.Prefix
	for current <= last {
		alignment := bits.TrailingZeros32(current)
		remaining := uint64(last) - uint64(current) + 1
		sizeBits := bits.Len64(remaining) - 1
		blockBits := min(alignment, sizeBits)
		result = append(result, netip.PrefixFrom(address4(current), 32-blockBits))
		current += uint32(1) << blockBits
		if current == 0 {
			break
		}
	}
	return result
}

func ipv6RangePrefixes(start, stop netip.Addr) []netip.Prefix {
	current := start.As16()
	last := stop.As16()
	var result []netip.Prefix
	for compare16(current, last) <= 0 {
		alignment := trailingZeros16(current)
		blockBits := alignment
		for blockBits > 0 && compare16(prefixLast16(current, 128-blockBits), last) > 0 {
			blockBits--
		}
		result = append(result, netip.PrefixFrom(netip.AddrFrom16(current), 128-blockBits))
		end := prefixLast16(current, 128-blockBits)
		next, overflow := increment16(end)
		if overflow {
			break
		}
		current = next
	}
	return result
}

func binaryAddress4(address netip.Addr) uint32 {
	value := address.As4()
	return uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
}

func address4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func trailingZeros16(value [16]byte) int {
	count := 0
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == 0 {
			count += 8
			continue
		}
		count += bits.TrailingZeros8(value[index])
		break
	}
	return count
}

func prefixLast16(address [16]byte, prefixLength int) [16]byte {
	result := address
	for bit := prefixLength; bit < 128; bit++ {
		result[bit/8] |= 1 << (7 - bit%8)
	}
	return result
}

func compare16(left, right [16]byte) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func increment16(value [16]byte) ([16]byte, bool) {
	for index := len(value) - 1; index >= 0; index-- {
		value[index]++
		if value[index] != 0 {
			return value, false
		}
	}
	return value, true
}

func sendEthernetFrame(interfaceName string, frame []byte) error {
	return sendEthernetFrameMarked(interfaceName, frame, 0)
}

func sendEthernetFrameMarked(interfaceName string, frame []byte, mark uint32) error {
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
			return err
		}
	}
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL), Ifindex: device.Index,
	})
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

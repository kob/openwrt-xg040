// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"net/netip"
	"testing"
	"time"
)

func TestServicePackageVLANOrderAndScalarProfileIgnored(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{
			profile(1, acl(1, "239.1.0.0", "239.1.0.255", 100)),
			profile(2, acl(2, "239.2.0.0", "239.2.0.255", 200)),
			profile(3, acl(3, "239.3.0.0", "239.3.0.255", 300)),
		},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1,
			ServicePackages: []ServicePackage{
				{RowKey: 9, VLANID: 4097, OperationsProfile: 3},
				{RowKey: 2, VLANID: 100, OperationsProfile: 2},
			},
		}},
	})

	decision := engine.Join(join(10, VLAN{Tagged: true, ID: 100}, "239.2.0.1"))
	if !decision.Accepted || decision.ProfileID != 2 || decision.ANIVLAN != 200 {
		t.Fatalf("exact service package decision = %+v", decision)
	}
	decision = engine.Join(join(10, VLAN{Tagged: true, ID: 101}, "239.3.0.1"))
	if !decision.Accepted || decision.ProfileID != 3 {
		t.Fatalf("tagged-wildcard service package decision = %+v", decision)
	}
	decision = engine.Join(join(10, VLAN{}, "239.1.0.1"))
	if decision.Accepted || decision.Reason != ReasonUnauthorized {
		t.Fatalf("scalar profile was used with non-empty package table: %+v", decision)
	}
}

func TestAuthorizationPrecedence(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	fullyAuthorized := acl(1, "239.1.0.1", "239.1.0.1", 100)
	preview := acl(2, "239.2.0.1", "239.2.0.2", 100)
	preview.PreviewLength = 30
	preview.PreviewRepeatTime = 60
	preview.PreviewRepeatCount = 1
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, fullyAuthorized, preview)},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1,
			AllowedPreviews: []AllowedPreview{{
				RowKey: 1, Source: addr("0.0.0.0"), Destination: addr("239.2.0.1"),
				ANIVLAN: 100, UNIVLAN: 100, Duration: 10, TimeLeft: 5,
			}},
		}},
	})

	tests := []struct {
		group  string
		reason Reason
	}{
		{group: "239.1.0.1", reason: ReasonAuthorized},
		{group: "239.2.0.1", reason: ReasonAllowedPreview},
		{group: "239.2.0.2", reason: ReasonPreview},
	}
	for _, test := range tests {
		decision := engine.Join(join(10, VLAN{Tagged: true, ID: 100}, test.group))
		if !decision.Accepted || decision.Reason != test.reason {
			t.Errorf("Join(%s) = %+v, want %s", test.group, decision, test.reason)
		}
	}
}

func TestUnauthorizedJoinForwarding(t *testing.T) {
	now := time.Now()
	configured := profile(1, acl(1, "239.1.0.0", "239.1.0.255", 100))
	configured.UnauthorizedJoinBehaviour = true
	engine := newPolicyEngine(t, &now, Config{
		Profiles:    []Profile{configured},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1}},
	})
	decision := engine.Join(join(10, VLAN{}, "239.2.0.1"))
	if decision.Accepted || decision.Replicate || !decision.ForwardUpstream ||
		decision.Reason != ReasonUnauthorized || decision.ProfileID != 1 {
		t.Fatalf("unauthorized forwarded join = %+v", decision)
	}
}

func TestGroupAndBandwidthLimits(t *testing.T) {
	now := time.Now()
	first := acl(1, "239.1.0.1", "239.1.0.1", 100)
	first.ImputedBandwidth = 600
	second := acl(2, "239.1.0.2", "239.1.0.2", 100)
	second.ImputedBandwidth = 500
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, first, second)},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1, MaxSimultaneousGroups: 2,
			MaxMulticastBandwidth: 1000, BandwidthEnforcement: true,
		}},
	})
	if decision := engine.Join(join(10, VLAN{}, "239.1.0.1")); !decision.Accepted {
		t.Fatalf("first join = %+v", decision)
	}
	decision := engine.Join(join(10, VLAN{}, "239.1.0.2"))
	if decision.Accepted || decision.ForwardUpstream || decision.Reason != ReasonBandwidthExceeded ||
		!decision.BandwidthExceeded {
		t.Fatalf("bandwidth-enforced join = %+v", decision)
	}
	monitor := engine.Monitor(10)
	if monitor.CurrentBandwidth != 600 || monitor.BandwidthExceeded != 1 || monitor.JoinMessages != 1 {
		t.Fatalf("monitor after denied join = %+v", monitor)
	}

	engine.config.subscribers[10] = compiledSubscriber{Subscriber: Subscriber{
		EntityID: 10, Profile: 1, MaxSimultaneousGroups: 1,
	}}
	decision = engine.Join(join(10, VLAN{}, "239.1.0.2"))
	if decision.Accepted || decision.ForwardUpstream || decision.Reason != ReasonGroupLimit {
		t.Fatalf("group-limited join = %+v", decision)
	}
}

func TestBandwidthExceededCanBeCountedAndHonoured(t *testing.T) {
	now := time.Now()
	entry := acl(1, "239.1.0.1", "239.1.0.1", 100)
	entry.ImputedBandwidth = 2000
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, entry)},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1, MaxMulticastBandwidth: 1000,
		}},
	})
	decision := engine.Join(join(10, VLAN{}, "239.1.0.1"))
	if !decision.Accepted || !decision.BandwidthExceeded {
		t.Fatalf("non-enforced bandwidth decision = %+v", decision)
	}
	if monitor := engine.Monitor(10); monitor.BandwidthExceeded != 1 || monitor.JoinMessages != 1 {
		t.Fatalf("non-enforced bandwidth monitor = %+v", monitor)
	}
}

func TestRepeatedJoinDoesNotConsumeAnotherLimit(t *testing.T) {
	now := time.Now()
	entry := acl(1, "239.1.0.1", "239.1.0.1", 100)
	entry.ImputedBandwidth = 1000
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, entry)},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1, MaxSimultaneousGroups: 1,
			MaxMulticastBandwidth: 1000, BandwidthEnforcement: true,
		}},
	})
	request := join(10, VLAN{}, "239.1.0.1")
	if !engine.Join(request).Accepted || !engine.Join(request).Accepted {
		t.Fatal("repeated join was denied")
	}
	monitor := engine.Monitor(10)
	if len(monitor.Groups) != 1 || monitor.CurrentBandwidth != 1000 || monitor.JoinMessages != 2 {
		t.Fatalf("monitor after repeated join = %+v", monitor)
	}
}

func TestMultipleClientsAreMonitoredWithoutDoubleCountingStream(t *testing.T) {
	now := time.Now()
	entry := acl(1, "239.1.0.1", "239.1.0.1", 100)
	entry.ImputedBandwidth = 1000
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, entry)},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1, MaxSimultaneousGroups: 1,
			MaxMulticastBandwidth: 1000, BandwidthEnforcement: true,
		}},
	})
	first := join(10, VLAN{}, "239.1.0.1")
	second := first
	second.Client = addr("192.0.2.11")
	if !engine.Join(first).Accepted || !engine.Join(second).Accepted {
		t.Fatal("same stream from two clients was denied")
	}
	monitor := engine.Monitor(10)
	if monitor.CurrentBandwidth != 1000 || monitor.JoinMessages != 2 || len(monitor.Groups) != 2 {
		t.Fatalf("multi-client monitor = %+v", monitor)
	}
	if !engine.Leave(first) {
		t.Fatal("first client leave was not recorded")
	}
	monitor = engine.Monitor(10)
	if monitor.CurrentBandwidth != 1000 || len(monitor.Groups) != 1 || monitor.Groups[0].Client != second.Client {
		t.Fatalf("monitor after one client left = %+v", monitor)
	}
}

func TestPreviewRepeatTimerCountAndDailyReset(t *testing.T) {
	now := time.Date(2026, 8, 11, 1, 58, 0, 0, time.UTC)
	entry := acl(1, "239.1.0.1", "239.1.0.1", 100)
	entry.PreviewLength = 30
	entry.PreviewRepeatTime = 60
	entry.PreviewRepeatCount = 1
	entry.PreviewResetTime = 2
	engine := newPolicyEngine(t, &now, Config{
		Profiles:    []Profile{profile(1, entry)},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1}},
	})
	request := join(10, VLAN{}, "239.1.0.1")
	first := engine.Join(request)
	if !first.Accepted || first.PreviewUntil != now.Add(30*time.Second) {
		t.Fatalf("first preview = %+v", first)
	}
	now = now.Add(31 * time.Second)
	engine.Expire()
	if decision := engine.Join(request); decision.Reason != ReasonPreviewInterval {
		t.Fatalf("join during repeat interval = %+v", decision)
	}
	now = now.Add(60 * time.Second)
	if decision := engine.Join(request); decision.Reason != ReasonPreviewExhausted {
		t.Fatalf("join after repeat interval = %+v", decision)
	}
	now = time.Date(2026, 8, 11, 2, 0, 1, 0, time.UTC)
	if decision := engine.Join(request); !decision.Accepted || decision.Reason != ReasonPreview {
		t.Fatalf("join after daily reset = %+v", decision)
	}
}

func TestAllowedPreviewExpires(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	entry := acl(1, "239.1.0.1", "239.1.0.1", 100)
	entry.PreviewLength = 10
	entry.PreviewRepeatCount = 1
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, entry)},
		Subscribers: []Subscriber{{
			EntityID: 10, Profile: 1,
			AllowedPreviews: []AllowedPreview{{
				RowKey: 1, Source: addr("0.0.0.0"), Destination: addr("239.1.0.1"),
				ANIVLAN: 100, UNIVLAN: 100, Duration: 2, TimeLeft: 1,
			}},
		}},
	})
	request := join(10, VLAN{Tagged: true, ID: 100}, "239.1.0.1")
	if decision := engine.Join(request); decision.Reason != ReasonAllowedPreview {
		t.Fatalf("allowed preview decision = %+v", decision)
	}
	now = now.Add(time.Minute + time.Second)
	if monitor := engine.Monitor(10); len(monitor.Groups) != 0 {
		t.Fatalf("allowed preview remained active after time-left expiry: %+v", monitor.Groups)
	}
	if decision := engine.Join(request); decision.Reason != ReasonPreview {
		t.Fatalf("expired allowed preview decision = %+v", decision)
	}
}

func TestAllowedPreviewTimersRoundUpAndExposeExpiry(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	engine := newPolicyEngine(t, &now, Config{
		Profiles: []Profile{profile(1, acl(1, "239.1.0.1", "239.1.0.1", 100))},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1, AllowedPreviews: []AllowedPreview{
			{RowKey: 7, Destination: addr("239.1.0.1"), Duration: 4, TimeLeft: 2},
			{RowKey: 9, Destination: addr("239.1.0.2"), Duration: 0, TimeLeft: 0},
		}}},
	})

	assertTimers := func(want uint16) {
		t.Helper()
		timers := engine.AllowedPreviewTimers(10)
		if len(timers) != 2 || timers[0] != (AllowedPreviewTimer{RowKey: 7, Duration: 4, TimeLeft: want}) ||
			timers[1] != (AllowedPreviewTimer{RowKey: 9}) {
			t.Fatalf("allowed-preview timers = %+v, want row 7 time-left %d and untimed row 9", timers, want)
		}
	}
	assertTimers(2)
	now = now.Add(time.Second)
	assertTimers(2)
	now = now.Add(time.Minute)
	assertTimers(1)
	now = now.Add(59 * time.Second)
	assertTimers(0)
}

func TestMonitorLeaveAndPreviewExpiry(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	regular := acl(1, "239.1.0.1", "239.1.0.1", 100)
	regular.ImputedBandwidth = 400
	preview := acl(2, "239.1.0.2", "239.1.0.2", 100)
	preview.ImputedBandwidth = 600
	preview.PreviewLength = 10
	engine := newPolicyEngine(t, &now, Config{
		Profiles:    []Profile{profile(1, regular, preview)},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1}},
	})
	first := join(10, VLAN{}, "239.1.0.1")
	second := join(10, VLAN{}, "239.1.0.2")
	engine.Join(first)
	engine.Join(second)
	now = now.Add(5 * time.Second)
	monitor := engine.Monitor(10)
	if monitor.CurrentBandwidth != 1000 || len(monitor.Groups) != 2 ||
		monitor.Groups[0].TimeSinceJoin != 5 {
		t.Fatalf("active monitor = %+v", monitor)
	}
	if !engine.Leave(first) || engine.Leave(first) {
		t.Fatal("leave result is inconsistent")
	}
	now = now.Add(6 * time.Second)
	expired := engine.Expire()
	if len(expired) != 1 || expired[0].Group != addr("239.1.0.2") {
		t.Fatalf("expired previews = %+v", expired)
	}
	if monitor := engine.Monitor(10); len(monitor.Groups) != 0 {
		t.Fatalf("groups remain after leave/expiry: %+v", monitor.Groups)
	}
}

func TestIPv6SourceSpecificACL(t *testing.T) {
	now := time.Now()
	entry := ACLEntry{
		RowKey: 1, IPVersion: 6, GEMPortID: 200, VLANID: 100,
		Source: addr("2001:db8::1"), Start: addr("ff3e::1"), Stop: addr("ff3e::ff"),
	}
	engine := newPolicyEngine(t, &now, Config{
		Profiles:    []Profile{profile(1, entry)},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 1}},
	})
	request := Join{
		SubscriberID: 10, UNIVLAN: VLAN{}, Source: addr("2001:db8::1"),
		Group: addr("ff3e::10"), Client: addr("2001:db8::100"),
	}
	if decision := engine.Join(request); !decision.Accepted {
		t.Fatalf("IPv6 source-specific join = %+v", decision)
	}
	request.Source = addr("2001:db8::2")
	if decision := engine.Join(request); decision.Accepted {
		t.Fatalf("wrong IPv6 source accepted: %+v", decision)
	}
}

func TestConfigValidation(t *testing.T) {
	now := time.Now()
	bad := acl(1, "192.0.2.1", "192.0.2.2", 100)
	if _, err := New(Config{Profiles: []Profile{profile(1, bad)}}, func() time.Time { return now }); err == nil {
		t.Fatal("non-multicast ACL range was accepted")
	}
	if _, err := New(Config{
		Profiles:    []Profile{profile(1)},
		Subscribers: []Subscriber{{EntityID: 10, Profile: 2}},
	}, func() time.Time { return now }); err == nil {
		t.Fatal("missing subscriber profile was accepted")
	}
}

func newPolicyEngine(t *testing.T, now *time.Time, config Config) *Engine {
	t.Helper()
	engine, err := New(config, func() time.Time { return *now })
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return engine
}

func profile(entityID uint16, entries ...ACLEntry) Profile {
	return Profile{EntityID: entityID, IGMPVersion: 3, DynamicACL: entries}
}

func acl(row uint16, start, stop string, vlan uint16) ACLEntry {
	return ACLEntry{
		RowKey: row, IPVersion: 4, GEMPortID: 200, VLANID: vlan,
		Source: addr("0.0.0.0"), Start: addr(start), Stop: addr(stop),
	}
}

func join(subscriber uint16, vlan VLAN, group string) Join {
	return Join{
		SubscriberID: subscriber, UNIVLAN: vlan, Source: addr("0.0.0.0"),
		Group: addr(group), Client: addr("192.0.2.10"),
	}
}

func addr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

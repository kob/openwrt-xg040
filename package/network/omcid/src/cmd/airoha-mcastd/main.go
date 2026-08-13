// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xg2010g/airoha-omci/internal/multicast"
	"github.com/xg2010g/airoha-omci/internal/platform"
)

var version = "devel"

type options struct {
	desired    string
	stateDir   string
	interfaces string
	tc         string
	validate   string
	poll       time.Duration
}

type monitorGroup struct {
	Source           string     `json:"source"`
	Group            string     `json:"group"`
	Client           string     `json:"client"`
	UNITagged        bool       `json:"uni_tagged"`
	UNIVLAN          uint16     `json:"uni_vlan"`
	ANIVLAN          uint16     `json:"ani_vlan"`
	ProfileID        uint16     `json:"profile_id"`
	ACLRowKey        uint16     `json:"acl_row_key"`
	GEMPortID        uint16     `json:"gem_port_id"`
	ImputedBandwidth uint32     `json:"imputed_bandwidth"`
	TimeSinceJoin    uint32     `json:"time_since_join"`
	PreviewUntil     *time.Time `json:"preview_until,omitempty"`
}

type previewTimer struct {
	RowKey   uint16 `json:"row_key"`
	Duration uint16 `json:"duration_minutes"`
	TimeLeft uint16 `json:"time_left_minutes"`
}

type monitorDocument struct {
	SubscriberID      uint16         `json:"multicast_subscriber_id"`
	MIBDataSync       uint8          `json:"mib_data_sync"`
	CurrentBandwidth  uint32         `json:"current_bandwidth"`
	JoinMessages      uint32         `json:"join_messages"`
	BandwidthExceeded uint32         `json:"bandwidth_exceeded"`
	Groups            []monitorGroup `json:"groups"`
	AllowedPreviews   []previewTimer `json:"allowed_previews"`
}

func main() {
	var opts options
	flag.StringVar(&opts.desired, "desired", "/var/run/airoha-omcid/desired.json",
		"atomic OMCI desired platform graph")
	flag.StringVar(&opts.stateDir, "state-dir", "/var/run/airoha-omci/multicast",
		"class 311 monitor state directory")
	flag.StringVar(&opts.interfaces, "interfaces", "lan1,lan2,lan3,lan4",
		"comma-separated UNI capture interfaces")
	flag.StringVar(&opts.tc, "tc", "/sbin/tc", "tc executable")
	flag.StringVar(&opts.validate, "validate", "", "validate one platform graph and exit")
	flag.DurationVar(&opts.poll, "poll", time.Second, "desired graph poll interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if opts.validate != "" {
		if err := validateDocument(opts.validate); err != nil {
			log.Printf("invalid multicast platform graph: %v", err)
			os.Exit(1)
		}
		return
	}
	if err := run(opts); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if opts.poll <= 0 {
		return fmt.Errorf("poll interval must be positive")
	}
	backend := multicast.NewLinuxBackend(multicast.LinuxBackendOptions{TC: opts.tc})
	runtime, err := multicast.NewRuntime(multicast.Config{}, backend, nil)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	for _, interfaceName := range parseInterfaces(opts.interfaces) {
		go captureLoop(ctx, runtime, interfaceName)
	}
	ticker := time.NewTicker(opts.poll)
	defer ticker.Stop()
	// Class 309 expresses last-member query intervals in 0.1 s units.
	expiry := time.NewTicker(100 * time.Millisecond)
	defer expiry.Stop()
	var appliedDocument [sha256.Size]byte
	var appliedPolicy [sha256.Size]byte
	var appliedMIBDataSync uint8
	loaded := false
	reload := func() {
		document, err := os.ReadFile(opts.desired)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("read desired graph: %v", err)
			}
			return
		}
		documentDigest := sha256.Sum256(document)
		if loaded && documentDigest == appliedDocument {
			return
		}
		request, err := platform.DecodeApplyRequest(bytes.NewReader(document))
		if err != nil {
			log.Printf("reject desired graph: %v", err)
			return
		}
		policy, err := request.Service.MulticastPolicy()
		if err != nil {
			log.Printf("resolve desired multicast policy: %v", err)
			return
		}
		policyDocument, err := json.Marshal(policy)
		if err != nil {
			log.Printf("encode desired multicast policy: %v", err)
			return
		}
		policyDigest := sha256.Sum256(policyDocument)
		if loaded && policyDigest == appliedPolicy {
			appliedDocument = documentDigest
			appliedMIBDataSync = request.MIBDataSync
			if err := publishMonitors(opts.stateDir, runtime, appliedMIBDataSync); err != nil {
				log.Printf("publish multicast monitors: %v", err)
			}
			return
		}
		if err := runtime.Configure(policy); err != nil {
			log.Printf("apply desired multicast policy: %v", err)
			return
		}
		appliedDocument, appliedPolicy = documentDigest, policyDigest
		appliedMIBDataSync, loaded = request.MIBDataSync, true
		log.Printf("applied multicast policy MIB data sync %d on %v",
			request.MIBDataSync, runtime.Interfaces())
		if err := publishMonitors(opts.stateDir, runtime, appliedMIBDataSync); err != nil {
			log.Printf("publish multicast monitors: %v", err)
		}
	}
	reload()
	if err := runtime.SampleBandwidth(); err != nil {
		log.Printf("sample multicast bandwidth: %v", err)
	}
	if err := publishMonitors(opts.stateDir, runtime, appliedMIBDataSync); err != nil {
		log.Printf("publish multicast monitors: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reload()
			if err := runtime.SampleBandwidth(); err != nil {
				log.Printf("sample multicast bandwidth: %v", err)
			}
			if err := publishMonitors(opts.stateDir, runtime, appliedMIBDataSync); err != nil {
				log.Printf("publish multicast monitors: %v", err)
			}
		case <-expiry.C:
			if err := runtime.Expire(); err != nil {
				log.Printf("advance multicast timers: %v", err)
			}
			if err := publishMonitors(opts.stateDir, runtime, appliedMIBDataSync); err != nil {
				log.Printf("publish multicast monitors: %v", err)
			}
		}
	}
}

func captureLoop(ctx context.Context, runtime *multicast.Runtime, interfaceName string) {
	for ctx.Err() == nil {
		err := multicast.CaptureMembership(ctx, interfaceName, func(message multicast.MembershipMessage) error {
			if err := runtime.Handle(interfaceName, message); err != nil {
				if managedInterface(runtime.Interfaces(), interfaceName) {
					log.Printf("process multicast report on %s: %v", interfaceName, err)
				}
			}
			return nil
		})
		if ctx.Err() != nil {
			return
		}
		log.Printf("capture multicast reports on %s: %v", interfaceName, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func parseInterfaces(value string) []string {
	seen := make(map[string]struct{})
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			seen[part] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for interfaceName := range seen {
		result = append(result, interfaceName)
	}
	sort.Strings(result)
	return result
}

func managedInterface(interfaces []string, wanted string) bool {
	index := sort.SearchStrings(interfaces, wanted)
	return index < len(interfaces) && interfaces[index] == wanted
}

func validateDocument(path string) error {
	document, err := os.Open(path)
	if err != nil {
		return err
	}
	defer document.Close()
	request, err := platform.DecodeApplyRequest(document)
	if err != nil {
		return err
	}
	policy, err := request.Service.MulticastPolicy()
	if err != nil {
		return err
	}
	backend := multicast.NewLinuxBackend(multicast.LinuxBackendOptions{
		Runner: discardRunner{}, Sender: func(string, []byte) error { return nil },
	})
	_, err = multicast.NewRuntime(policy, backend, nil)
	return err
}

type discardRunner struct{}

func (discardRunner) Run(string, ...string) error { return nil }

func publishMonitors(directory string, runtime *multicast.Runtime, mibDataSync uint8) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	active := make(map[uint16]struct{})
	for _, entityID := range runtime.SubscriberIDs() {
		active[entityID] = struct{}{}
		monitor := runtime.Monitor(entityID)
		document := monitorDocument{SubscriberID: entityID, MIBDataSync: mibDataSync,
			CurrentBandwidth: monitor.CurrentBandwidth, JoinMessages: monitor.JoinMessages,
			BandwidthExceeded: monitor.BandwidthExceeded,
			Groups:            make([]monitorGroup, 0, len(monitor.Groups)),
			AllowedPreviews:   make([]previewTimer, 0)}
		for _, group := range monitor.Groups {
			value := monitorGroup{Source: group.Source.String(), Group: group.Group.String(),
				Client: group.Client.String(), UNITagged: group.UNIVLAN.Tagged,
				UNIVLAN: group.UNIVLAN.ID, ANIVLAN: group.ANIVLAN,
				ProfileID: group.ProfileID, ACLRowKey: group.ACLRowKey, GEMPortID: group.GEMPortID,
				ImputedBandwidth: group.ImputedBandwidth, TimeSinceJoin: group.TimeSinceJoin}
			if !group.PreviewUntil.IsZero() {
				expires := group.PreviewUntil.UTC()
				value.PreviewUntil = &expires
			}
			document.Groups = append(document.Groups, value)
		}
		for _, timer := range runtime.AllowedPreviewTimers(entityID) {
			document.AllowedPreviews = append(document.AllowedPreviews, previewTimer{
				RowKey: timer.RowKey, Duration: timer.Duration, TimeLeft: timer.TimeLeft,
			})
		}
		if err := writeAtomicJSON(filepath.Join(directory, strconv.Itoa(int(entityID))+".json"), document); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".json"), 10, 16)
		if err != nil {
			continue
		}
		if _, exists := active[uint16(value)]; !exists {
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func writeAtomicJSON(path string, value interface{}) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".monitor-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

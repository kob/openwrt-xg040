// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecControllerEncodesActions(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "control.json")
	helper := filepath.Join(directory, "control")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ncat > "+output+"\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	controller := ExecController{Path: helper}
	if err := controller.SynchronizeTime(time.Unix(1234, 0)); err != nil {
		t.Fatalf("SynchronizeTime() error = %v", err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"synchronize-time"`) ||
		!strings.Contains(string(payload), `"unix_time":1234`) {
		t.Fatalf("payload = %s", payload)
	}
}

func TestExecControllerReadsOpticalDiagnostics(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	helper := filepath.Join(directory, "control")
	script := "#!/bin/sh\ncat > " + requestPath + "\n" +
		"printf '%s\\n' '{\"temperature\":62976,\"supply_voltage\":33000,\"laser_bias_current\":2500,\"transmit_power\":10000,\"receive_power\":10}'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	diagnostics, err := (ExecController{Path: helper}).OpticalLineSupervision()
	if err != nil {
		t.Fatalf("OpticalLineSupervision() error = %v", err)
	}
	if diagnostics.PowerFeedVoltage != 165 || diagnostics.ReceivedOpticalPower != 0 ||
		diagnostics.MeanOpticalLaunch != 15000 || diagnostics.LaserBiasCurrent != 2500 ||
		diagnostics.Temperature != 0xf600 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	payload, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request) error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"optical-line-supervision"`) {
		t.Fatalf("request = %s", payload)
	}
}

func TestExecControllerRejectsIncompleteOpticalDiagnostics(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "control")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '{\"temperature\":0}'\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecController{Path: helper}).OpticalLineSupervision(); err == nil ||
		!strings.Contains(err.Error(), "required field is missing") {
		t.Fatalf("OpticalLineSupervision() error = %v", err)
	}
}

func TestExecControllerReadsGEMPortCounters(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	helper := filepath.Join(directory, "control")
	script := "#!/bin/sh\ncat > " + requestPath + "\n" +
		"printf '%s\\n' '{\"gem_port_id\":42,\"received_gem_frames\":11,\"received_payload_bytes\":22,\"transmitted_gem_frames\":33,\"transmitted_payload_bytes\":44}'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	counters, err := (ExecController{Path: helper}).GEMPortCounters(42)
	if err != nil {
		t.Fatalf("GEMPortCounters() error = %v", err)
	}
	if counters.ReceivedGEMFrames != 11 || counters.ReceivedPayloadBytes != 22 ||
		counters.TransmittedGEMFrames != 33 || counters.TransmittedPayloadBytes != 44 {
		t.Fatalf("counters = %#v", counters)
	}
	payload, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request) error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"gem-port-counters"`) ||
		!strings.Contains(string(payload), `"gem_port_id":42`) {
		t.Fatalf("request = %s", payload)
	}
}

func TestExecControllerRejectsMismatchedGEMPortCounters(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "control")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '{\"gem_port_id\":7,\"received_gem_frames\":0,\"received_payload_bytes\":0,\"transmitted_gem_frames\":0,\"transmitted_payload_bytes\":0}'\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecController{Path: helper}).GEMPortCounters(42); err == nil ||
		!strings.Contains(err.Error(), "matching field") {
		t.Fatalf("GEMPortCounters() error = %v", err)
	}
}

func TestExecControllerReadsFECCounters(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	helper := filepath.Join(directory, "control")
	script := "#!/bin/sh\ncat > " + requestPath + "\n" +
		"printf '%s\\n' '{\"ani_entity_id\":32769,\"corrected_bytes\":11,\"corrected_codewords\":22,\"uncorrectable_codewords\":33,\"total_codewords\":44,\"fec_seconds\":55}'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	counters, err := (ExecController{Path: helper}).FECCounters(0x8001)
	if err != nil {
		t.Fatalf("FECCounters() error = %v", err)
	}
	if counters.CorrectedBytes != 11 || counters.CorrectedCodeWords != 22 ||
		counters.UncorrectableCodeWords != 33 || counters.TotalCodeWords != 44 ||
		counters.FECSeconds != 55 {
		t.Fatalf("FEC counters = %#v", counters)
	}
	payload, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request) error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"fec-counters"`) ||
		!strings.Contains(string(payload), `"ani_entity_id":32769`) {
		t.Fatalf("request = %s", payload)
	}
}

func TestExecControllerRejectsIncompleteFECCounters(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "control")
	response := `{"ani_entity_id":32769,"corrected_bytes":0}`
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '"+response+"'\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecController{Path: helper}).FECCounters(0x8001); err == nil ||
		!strings.Contains(err.Error(), "required or matching field") {
		t.Fatalf("FECCounters() error = %v", err)
	}
}

func TestExecControllerReadsEthernetCounters(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	helper := filepath.Join(directory, "control")
	response := `{"ethernet_entity_id":257,"received":{"frames":1,"octets":2,"drop_events":3,"broadcast_frames":4,"multicast_frames":5,"crc_errors":6,"buffer_overflows":7,"internal_errors":8,"undersize_frames":9,"fragments":10,"jabbers":11,"oversize_frames":12,"size_buckets":[13,14,15,16,17,18]},"transmitted":{"frames":21,"octets":22,"drop_events":23,"broadcast_frames":24,"multicast_frames":25,"crc_errors":26,"buffer_overflows":27,"internal_errors":28,"undersize_frames":29,"fragments":30,"jabbers":31,"oversize_frames":32,"size_buckets":[33,34,35,36,37,38]}}`
	script := "#!/bin/sh\ncat > " + requestPath + "\n" +
		"printf '%s\\n' '" + response + "'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	counters, err := (ExecController{Path: helper}).EthernetCounters(0x0101)
	if err != nil {
		t.Fatalf("EthernetCounters() error = %v", err)
	}
	if counters.Received.Frames != 1 || counters.Received.CRCErrors != 6 ||
		counters.Received.SizeBuckets[5] != 18 || counters.Transmitted.Frames != 21 ||
		counters.Transmitted.OversizeFrames != 32 || counters.Transmitted.SizeBuckets[5] != 38 {
		t.Fatalf("Ethernet counters = %#v", counters)
	}
	payload, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request) error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"ethernet-counters"`) ||
		!strings.Contains(string(payload), `"ethernet_entity_id":257`) {
		t.Fatalf("request = %s", payload)
	}
}

func TestExecControllerRejectsIncompleteEthernetCounters(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "control")
	script := "#!/bin/sh\nprintf '%s\\n' " +
		"'{\"ethernet_entity_id\":257,\"received\":{},\"transmitted\":{}}'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecController{Path: helper}).EthernetCounters(0x0101); err == nil ||
		!strings.Contains(err.Error(), "required received field") {
		t.Fatalf("EthernetCounters() error = %v", err)
	}
}

func TestExecControllerReadsMulticastSubscriberMonitor(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	helper := filepath.Join(directory, "control")
	response := `{"multicast_subscriber_id":1280,"current_bandwidth":1000000,"join_messages":7,"bandwidth_exceeded":2,"groups":[{"source":"0.0.0.0","group":"239.1.2.3","client":"192.0.2.10","uni_tagged":true,"uni_vlan":100,"ani_vlan":200,"profile_id":1792,"acl_row_key":9,"gem_port_id":203,"imputed_bandwidth":1000000,"time_since_join":45}]}`
	script := "#!/bin/sh\ncat > " + requestPath + "\n" +
		"printf '%s\\n' '" + response + "'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	monitor, err := (ExecController{Path: helper}).SubscriberMonitor(1280)
	if err != nil {
		t.Fatalf("SubscriberMonitor() error = %v", err)
	}
	if monitor.CurrentBandwidth != 1_000_000 || monitor.JoinMessages != 7 ||
		monitor.BandwidthExceeded != 2 || len(monitor.Groups) != 1 ||
		monitor.Groups[0].Group != netip.MustParseAddr("239.1.2.3") ||
		monitor.Groups[0].Client != netip.MustParseAddr("192.0.2.10") ||
		!monitor.Groups[0].UNIVLAN.Tagged || monitor.Groups[0].UNIVLAN.ID != 100 ||
		monitor.Groups[0].GEMPortID != 203 {
		t.Fatalf("multicast monitor = %#v", monitor)
	}
	payload, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request) error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"multicast-subscriber-monitor"`) ||
		!strings.Contains(string(payload), `"multicast_subscriber_id":1280`) {
		t.Fatalf("request = %s", payload)
	}
}

func TestExecControllerRejectsIncompleteMulticastSubscriberMonitor(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "control")
	response := `{"multicast_subscriber_id":1280,"current_bandwidth":0,"join_messages":0,"bandwidth_exceeded":0,"groups":[{}]}`
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '"+response+"'\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecController{Path: helper}).SubscriberMonitor(1280); err == nil ||
		!strings.Contains(err.Error(), "group 0 is incomplete") {
		t.Fatalf("SubscriberMonitor() error = %v", err)
	}
}

func TestExecControllerReadsAllowedPreviewStatus(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	helper := filepath.Join(directory, "control")
	response := `{"multicast_subscriber_id":1280,"mib_data_sync":17,"current_bandwidth":0,"join_messages":0,"bandwidth_exceeded":0,"groups":[],"allowed_previews":[{"row_key":7,"duration_minutes":60,"time_left_minutes":23}]}`
	script := "#!/bin/sh\ncat > " + requestPath + "\n" +
		"printf '%s\\n' '" + response + "'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	snapshot, err := (ExecController{Path: helper}).AllowedPreviewStatus(1280)
	if err != nil {
		t.Fatalf("AllowedPreviewStatus() error = %v", err)
	}
	if snapshot.MIBDataSync != 17 || len(snapshot.Timers) != 1 ||
		snapshot.Timers[0].RowKey != 7 || snapshot.Timers[0].Duration != 60 ||
		snapshot.Timers[0].TimeLeft != 23 {
		t.Fatalf("allowed-preview snapshot = %+v", snapshot)
	}
	payload, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request) error = %v", err)
	}
	if !strings.Contains(string(payload), `"action":"multicast-preview-status"`) ||
		!strings.Contains(string(payload), `"multicast_subscriber_id":1280`) {
		t.Fatalf("request = %s", payload)
	}
}

func TestExecControllerRejectsInvalidAllowedPreviewStatus(t *testing.T) {
	for name, response := range map[string]string{
		"missing timer field":   `{"multicast_subscriber_id":1280,"mib_data_sync":1,"allowed_previews":[{"row_key":7,"duration_minutes":60}]}`,
		"time exceeds duration": `{"multicast_subscriber_id":1280,"mib_data_sync":1,"allowed_previews":[{"row_key":7,"duration_minutes":60,"time_left_minutes":61}]}`,
		"duplicate key":         `{"multicast_subscriber_id":1280,"mib_data_sync":1,"allowed_previews":[{"row_key":7,"duration_minutes":60,"time_left_minutes":1},{"row_key":7,"duration_minutes":60,"time_left_minutes":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			helper := filepath.Join(t.TempDir(), "control")
			if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '"+response+"'\n"), 0o755); err != nil {
				t.Fatalf("WriteFile(helper) error = %v", err)
			}
			if _, err := (ExecController{Path: helper}).AllowedPreviewStatus(1280); err == nil {
				t.Fatal("AllowedPreviewStatus() unexpectedly accepted invalid state")
			}
		})
	}
}

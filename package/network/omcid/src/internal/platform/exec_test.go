// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
)

func TestDecodeApplyRequestIsStrict(t *testing.T) {
	valid := `{"version":7,"state_domain":"xg2010g:gpon","operation":"reset","mib_data_sync":0,"mib_state":{"version":1,"state_domain":"xg2010g:gpon","mib_data_sync":0,"instances":[{"class_id":2,"entity_id":0,"origin":0,"attributes":[{"name":"MibDataSync","kind":"uint8"}]}]},"service_graph":{"unis":[],"tconts":[],"traffic_descriptors":[],"dot1_rate_limiters":[],"gem_ports":[],"gem_interworking":[],"multicast_gem_interworking":[],"multicast_operations_profiles":[],"multicast_subscribers":[],"pbit_mappers":[],"bridges":[],"vlan_filters":[],"vlan_operations":[],"extended_vlans":[]}}`
	request, err := DecodeApplyRequest(bytes.NewBufferString(valid))
	if err != nil || request.Operation != mib.OperationReset {
		t.Fatalf("DecodeApplyRequest(valid) = %#v, %v", request, err)
	}
	for _, document := range []string{
		strings.Replace(valid, `"version":7`, `"version":6`, 1),
		strings.Replace(valid, `"state_domain":"xg2010g:gpon"`, `"state_domain":""`, 1),
		strings.Replace(valid, `"state_domain":"xg2010g:gpon"`, `"state_domain":"xg2010g:xgspon"`, 1),
		strings.Replace(valid, `"operation":"reset"`, `"operation":"other"`, 1),
		strings.Replace(valid, `"mib_data_sync":0`, `"mib_data_sync":0,"unknown":1`, 1),
		strings.Replace(valid, `"mib_data_sync":0,"mib_state"`, `"mib_data_sync":1,"mib_state"`, 1),
		strings.Replace(valid, `"mib_state":{`, `"mib_state":null,"unused":{`, 1),
		valid + `{}`,
	} {
		if _, err := DecodeApplyRequest(bytes.NewBufferString(document)); err == nil {
			t.Fatalf("DecodeApplyRequest(%s) unexpectedly succeeded", document)
		}
	}
}

func TestDecodeApplyRequestAcceptsAutonomousOperation(t *testing.T) {
	document := `{"version":7,"state_domain":"xg2010g:gpon","operation":"autonomous","mib_data_sync":9,"mib_state":{"version":1,"state_domain":"xg2010g:gpon","mib_data_sync":9,"instances":[{"class_id":2,"entity_id":0,"origin":0,"attributes":[{"name":"MibDataSync","kind":"uint8","unsigned":9}]}]},"service_graph":{"unis":[],"tconts":[],"traffic_descriptors":[],"dot1_rate_limiters":[],"gem_ports":[],"gem_interworking":[],"multicast_gem_interworking":[],"multicast_operations_profiles":[],"multicast_subscribers":[],"pbit_mappers":[],"bridges":[],"vlan_filters":[],"vlan_operations":[],"extended_vlans":[]}}`
	request, err := DecodeApplyRequest(bytes.NewBufferString(document))
	if err != nil || request.Operation != mib.OperationAutonomous || request.MIBDataSync != 9 {
		t.Fatalf("DecodeApplyRequest(autonomous) = %#v, %v", request, err)
	}
}

func TestExecApplierPassesCandidateAsJSON(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "change.json")
	helper := filepath.Join(directory, "apply")
	script := "#!/bin/sh\ncat > " + output + "\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}

	change := mib.Change{
		Operation:   mib.OperationReset,
		StateDomain: "xg2010g:gpon",
		MIBDataSync: 7,
		Snapshot: []mib.Instance{
			{
				Key:        mib.Key{ClassID: me.OnuDataClassID},
				Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(7)},
			},
			{
				Key:        mib.Key{ClassID: me.TContClassID, EntityID: 0x8001},
				Attributes: me.AttributeValueMap{me.TCont_AllocId: uint16(100)},
			},
		},
	}
	if err := (ExecApplier{Path: helper}).Apply(change); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile(output) error = %v", err)
	}
	var request ApplyRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("Unmarshal(payload) error = %v", err)
	}
	if request.Version != ApplyABIVersion || request.StateDomain != "xg2010g:gpon" ||
		request.Operation != mib.OperationReset ||
		request.MIBDataSync != 7 || len(request.Service.TCONTs) != 1 ||
		request.Service.TCONTs[0].AllocID != 100 || request.MIBState == nil ||
		request.MIBState.MIBDataSync != 7 || len(request.MIBState.Instances) != 2 {
		t.Fatalf("request = %#v", request)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("Unmarshal(raw payload) error = %v", err)
	}
	if _, exists := raw["snapshot"]; exists || raw["mib_state"] == nil {
		t.Fatalf("platform payload has invalid MIB state boundary: %s", payload)
	}
}

func TestExecApplierUsesRecordForCommand(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "arguments")
	helper := filepath.Join(directory, "apply")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > " + output + "\ncat >/dev/null\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	change := mib.Change{Operation: mib.OperationCommand, StateDomain: "xg2010g:gpon", Snapshot: []mib.Instance{{
		Key:        mib.Key{ClassID: me.OnuDataClassID},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}}
	if err := (ExecApplier{Path: helper}).Apply(change); err != nil {
		t.Fatalf("Apply(command) error = %v", err)
	}
	arguments, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile(arguments) error = %v", err)
	}
	if string(arguments) != "record\n" {
		t.Fatalf("helper arguments = %q, want record", arguments)
	}
}

func TestExecApplierReportsHelperFailure(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "apply")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho rejected >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	err := (ExecApplier{Path: helper}).Apply(mib.Change{StateDomain: "xg2010g:gpon", Snapshot: []mib.Instance{{
		Key:        mib.Key{ClassID: me.OnuDataClassID},
		Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
	}}})
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("Apply() error = %v, want helper detail", err)
	}
}

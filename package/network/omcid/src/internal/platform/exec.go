// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/multicast"
)

const defaultApplyTimeout = 10 * time.Second

const ApplyABIVersion = 7

// ApplyRequest is the versioned boundary between the G.988 engine and a
// privileged platform helper. The helper consumes resolved connectivity, not
// raw managed-entity attributes.
type ApplyRequest struct {
	Version     uint8         `json:"version"`
	StateDomain string        `json:"state_domain"`
	Operation   mib.Operation `json:"operation"`
	MIBDataSync uint8         `json:"mib_data_sync"`
	MIBState    *mib.State    `json:"mib_state"`
	Service     ServiceGraph  `json:"service_graph"`
}

// DecodeApplyRequest strictly decodes and validates the platform ABI. Native
// backends use the same parser as the transactional apply path, so a persisted
// desired graph cannot acquire a second, more permissive interpretation.
func DecodeApplyRequest(reader io.Reader) (ApplyRequest, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var request ApplyRequest
	if err := decoder.Decode(&request); err != nil {
		return ApplyRequest{}, fmt.Errorf("decode platform request: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ApplyRequest{}, fmt.Errorf("decode platform request: trailing JSON value")
		}
		return ApplyRequest{}, fmt.Errorf("decode platform request: %w", err)
	}
	if request.Version != ApplyABIVersion {
		return ApplyRequest{}, fmt.Errorf("unsupported platform ABI %d", request.Version)
	}
	if request.StateDomain == "" {
		return ApplyRequest{}, fmt.Errorf("platform request has no state domain")
	}
	switch request.Operation {
	case mib.OperationCreate, mib.OperationSet, mib.OperationSetTable,
		mib.OperationDelete, mib.OperationReset, mib.OperationCommand,
		mib.OperationAutonomous:
	default:
		return ApplyRequest{}, fmt.Errorf("invalid platform operation %q", request.Operation)
	}
	if request.MIBState == nil {
		return ApplyRequest{}, fmt.Errorf("platform request has no MIB state")
	}
	if request.MIBState.StateDomain != request.StateDomain {
		return ApplyRequest{}, fmt.Errorf("platform state domain %q does not match MIB state %q",
			request.StateDomain, request.MIBState.StateDomain)
	}
	if err := request.MIBState.Validate(); err != nil {
		return ApplyRequest{}, fmt.Errorf("invalid platform MIB state: %w", err)
	}
	if request.MIBState.MIBDataSync != request.MIBDataSync {
		return ApplyRequest{}, fmt.Errorf("platform MIB data sync %d does not match state %d",
			request.MIBDataSync, request.MIBState.MIBDataSync)
	}
	policy, err := request.Service.MulticastPolicy()
	if err != nil {
		return ApplyRequest{}, err
	}
	if err := multicast.Validate(policy); err != nil {
		return ApplyRequest{}, err
	}
	return request, nil
}

// ExecApplier resolves and sends one complete candidate service graph to a
// fixed helper. No shell is involved. A non-zero helper exit rejects the OMCI
// mutation.
type ExecApplier struct {
	Path    string
	Timeout time.Duration
}

func (a ExecApplier) Apply(change mib.Change) error {
	if a.Path == "" {
		return fmt.Errorf("platform apply helper is empty")
	}
	graph, err := BuildServiceGraph(change.Snapshot)
	if err != nil {
		return err
	}
	policy, err := graph.MulticastPolicy()
	if err != nil {
		return err
	}
	if err := multicast.Validate(policy); err != nil {
		return err
	}
	if change.StateDomain == "" {
		return fmt.Errorf("platform change has no state domain")
	}
	mibState, err := mib.ExportState(change.Snapshot, change.MIBDataSync, change.StateDomain)
	if err != nil {
		return err
	}
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = defaultApplyTimeout
	}
	payload, err := json.Marshal(ApplyRequest{
		Version:     ApplyABIVersion,
		StateDomain: change.StateDomain,
		Operation:   change.Operation,
		MIBDataSync: change.MIBDataSync,
		MIBState:    &mibState,
		Service:     graph,
	})
	if err != nil {
		return fmt.Errorf("encode platform change: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	arguments := []string(nil)
	if change.Operation == mib.OperationCommand {
		arguments = []string{"record"}
	}
	command := exec.CommandContext(ctx, a.Path, arguments...)
	command.Stdin = bytes.NewReader(payload)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("platform helper timed out after %s: %w", timeout, ctx.Err())
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return fmt.Errorf("platform helper: %w", err)
		}
		return fmt.Errorf("platform helper: %w: %s", err, detail)
	}
	return nil
}

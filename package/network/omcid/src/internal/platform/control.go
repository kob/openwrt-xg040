// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/xg2010g/airoha-omci/internal/multicast"
	"github.com/xg2010g/airoha-omci/internal/optical"
	"github.com/xg2010g/airoha-omci/internal/performance"
)

type ExecController struct {
	Path    string
	Timeout time.Duration
}

type controlRequest struct {
	Action                string  `json:"action"`
	UnixTime              int64   `json:"unix_time,omitempty"`
	RebootCondition       uint8   `json:"reboot_condition,omitempty"`
	GEMPortID             *uint16 `json:"gem_port_id,omitempty"`
	ANIEntityID           *uint16 `json:"ani_entity_id,omitempty"`
	EthernetEntityID      *uint16 `json:"ethernet_entity_id,omitempty"`
	MulticastSubscriberID *uint16 `json:"multicast_subscriber_id,omitempty"`
}

type ethernetDirectionResponse struct {
	Frames          *uint64    `json:"frames"`
	Octets          *uint64    `json:"octets"`
	DropEvents      *uint64    `json:"drop_events"`
	BroadcastFrames *uint64    `json:"broadcast_frames"`
	MulticastFrames *uint64    `json:"multicast_frames"`
	CRCErrors       *uint64    `json:"crc_errors"`
	BufferOverflows *uint64    `json:"buffer_overflows"`
	InternalErrors  *uint64    `json:"internal_errors"`
	UndersizeFrames *uint64    `json:"undersize_frames"`
	Fragments       *uint64    `json:"fragments"`
	Jabbers         *uint64    `json:"jabbers"`
	OversizeFrames  *uint64    `json:"oversize_frames"`
	SizeBuckets     *[6]uint64 `json:"size_buckets"`
}

type multicastGroupResponse struct {
	Source           *string    `json:"source"`
	Group            *string    `json:"group"`
	Client           *string    `json:"client"`
	UNITagged        *bool      `json:"uni_tagged"`
	UNIVLAN          *uint16    `json:"uni_vlan"`
	ANIVLAN          *uint16    `json:"ani_vlan"`
	ProfileID        *uint16    `json:"profile_id"`
	ACLRowKey        *uint16    `json:"acl_row_key"`
	GEMPortID        *uint16    `json:"gem_port_id"`
	ImputedBandwidth *uint32    `json:"imputed_bandwidth"`
	TimeSinceJoin    *uint32    `json:"time_since_join"`
	PreviewUntil     *time.Time `json:"preview_until,omitempty"`
}

type multicastPreviewResponse struct {
	RowKey   *uint16 `json:"row_key"`
	Duration *uint16 `json:"duration_minutes"`
	TimeLeft *uint16 `json:"time_left_minutes"`
}

type multicastStateResponse struct {
	SubscriberID      *uint16                     `json:"multicast_subscriber_id"`
	MIBDataSync       *uint8                      `json:"mib_data_sync"`
	CurrentBandwidth  *uint32                     `json:"current_bandwidth"`
	JoinMessages      *uint32                     `json:"join_messages"`
	BandwidthExceeded *uint32                     `json:"bandwidth_exceeded"`
	Groups            *[]multicastGroupResponse   `json:"groups"`
	AllowedPreviews   *[]multicastPreviewResponse `json:"allowed_previews"`
}

func (c ExecController) GEMPortCounters(portID uint16) (performance.GEMPortCounters, error) {
	output, err := c.execute(controlRequest{Action: "gem-port-counters", GEMPortID: &portID})
	if err != nil {
		return performance.GEMPortCounters{}, err
	}
	type response struct {
		GEMPortID               *uint16 `json:"gem_port_id"`
		ReceivedGEMFrames       *uint64 `json:"received_gem_frames"`
		ReceivedPayloadBytes    *uint64 `json:"received_payload_bytes"`
		TransmittedGEMFrames    *uint64 `json:"transmitted_gem_frames"`
		TransmittedPayloadBytes *uint64 `json:"transmitted_payload_bytes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var value response
	if err := decoder.Decode(&value); err != nil {
		return performance.GEMPortCounters{}, fmt.Errorf("decode GEM port counters: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return performance.GEMPortCounters{}, fmt.Errorf("decode GEM port counters: trailing JSON value")
		}
		return performance.GEMPortCounters{}, fmt.Errorf("decode GEM port counters: %w", err)
	}
	if value.GEMPortID == nil || *value.GEMPortID != portID ||
		value.ReceivedGEMFrames == nil || value.ReceivedPayloadBytes == nil ||
		value.TransmittedGEMFrames == nil || value.TransmittedPayloadBytes == nil {
		return performance.GEMPortCounters{}, fmt.Errorf("decode GEM port counters: required or matching field is missing")
	}
	return performance.GEMPortCounters{
		ReceivedGEMFrames:       *value.ReceivedGEMFrames,
		ReceivedPayloadBytes:    *value.ReceivedPayloadBytes,
		TransmittedGEMFrames:    *value.TransmittedGEMFrames,
		TransmittedPayloadBytes: *value.TransmittedPayloadBytes,
	}, nil
}

func (c ExecController) FECCounters(entityID uint16) (performance.FECCounters, error) {
	output, err := c.execute(controlRequest{Action: "fec-counters", ANIEntityID: &entityID})
	if err != nil {
		return performance.FECCounters{}, err
	}
	type response struct {
		ANIEntityID            *uint16 `json:"ani_entity_id"`
		CorrectedBytes         *uint64 `json:"corrected_bytes"`
		CorrectedCodeWords     *uint64 `json:"corrected_codewords"`
		UncorrectableCodeWords *uint64 `json:"uncorrectable_codewords"`
		TotalCodeWords         *uint64 `json:"total_codewords"`
		FECSeconds             *uint64 `json:"fec_seconds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var value response
	if err := decoder.Decode(&value); err != nil {
		return performance.FECCounters{}, fmt.Errorf("decode FEC counters: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return performance.FECCounters{}, fmt.Errorf("decode FEC counters: trailing JSON value")
		}
		return performance.FECCounters{}, fmt.Errorf("decode FEC counters: %w", err)
	}
	if value.ANIEntityID == nil || *value.ANIEntityID != entityID ||
		value.CorrectedBytes == nil || value.CorrectedCodeWords == nil ||
		value.UncorrectableCodeWords == nil || value.TotalCodeWords == nil ||
		value.FECSeconds == nil {
		return performance.FECCounters{}, fmt.Errorf(
			"decode FEC counters: required or matching field is missing")
	}
	return performance.FECCounters{
		CorrectedBytes:         *value.CorrectedBytes,
		CorrectedCodeWords:     *value.CorrectedCodeWords,
		UncorrectableCodeWords: *value.UncorrectableCodeWords,
		TotalCodeWords:         *value.TotalCodeWords,
		FECSeconds:             *value.FECSeconds,
	}, nil
}

func (c ExecController) EthernetCounters(entityID uint16) (performance.EthernetCounters, error) {
	output, err := c.execute(controlRequest{
		Action: "ethernet-counters", EthernetEntityID: &entityID,
	})
	if err != nil {
		return performance.EthernetCounters{}, err
	}
	type response struct {
		EthernetEntityID *uint16                    `json:"ethernet_entity_id"`
		Received         *ethernetDirectionResponse `json:"received"`
		Transmitted      *ethernetDirectionResponse `json:"transmitted"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var value response
	if err := decoder.Decode(&value); err != nil {
		return performance.EthernetCounters{}, fmt.Errorf("decode Ethernet counters: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return performance.EthernetCounters{}, fmt.Errorf("decode Ethernet counters: trailing JSON value")
		}
		return performance.EthernetCounters{}, fmt.Errorf("decode Ethernet counters: %w", err)
	}
	if value.EthernetEntityID == nil || *value.EthernetEntityID != entityID ||
		value.Received == nil || value.Transmitted == nil {
		return performance.EthernetCounters{}, fmt.Errorf(
			"decode Ethernet counters: required or matching field is missing")
	}
	received, err := decodeEthernetDirection("received", value.Received)
	if err != nil {
		return performance.EthernetCounters{}, err
	}
	transmitted, err := decodeEthernetDirection("transmitted", value.Transmitted)
	if err != nil {
		return performance.EthernetCounters{}, err
	}
	return performance.EthernetCounters{Received: received, Transmitted: transmitted}, nil
}

func decodeEthernetDirection(name string,
	value *ethernetDirectionResponse) (performance.EthernetDirectionCounters, error) {
	if value.Frames == nil || value.Octets == nil || value.DropEvents == nil ||
		value.BroadcastFrames == nil || value.MulticastFrames == nil ||
		value.CRCErrors == nil || value.BufferOverflows == nil || value.InternalErrors == nil ||
		value.UndersizeFrames == nil || value.Fragments == nil || value.Jabbers == nil ||
		value.OversizeFrames == nil || value.SizeBuckets == nil {
		return performance.EthernetDirectionCounters{}, fmt.Errorf(
			"decode Ethernet counters: required %s field is missing", name)
	}
	return performance.EthernetDirectionCounters{
		Frames:          *value.Frames,
		Octets:          *value.Octets,
		DropEvents:      *value.DropEvents,
		BroadcastFrames: *value.BroadcastFrames,
		MulticastFrames: *value.MulticastFrames,
		CRCErrors:       *value.CRCErrors,
		BufferOverflows: *value.BufferOverflows,
		InternalErrors:  *value.InternalErrors,
		UndersizeFrames: *value.UndersizeFrames,
		Fragments:       *value.Fragments,
		Jabbers:         *value.Jabbers,
		OversizeFrames:  *value.OversizeFrames,
		SizeBuckets:     *value.SizeBuckets,
	}, nil
}

func (c ExecController) SubscriberMonitor(entityID uint16) (multicast.Monitor, error) {
	output, err := c.execute(controlRequest{
		Action: "multicast-subscriber-monitor", MulticastSubscriberID: &entityID,
	})
	if err != nil {
		return multicast.Monitor{}, err
	}
	value, err := decodeMulticastState(output, entityID)
	if err != nil {
		return multicast.Monitor{}, fmt.Errorf("decode multicast subscriber monitor: %w", err)
	}
	if value.CurrentBandwidth == nil || value.JoinMessages == nil ||
		value.BandwidthExceeded == nil || value.Groups == nil {
		return multicast.Monitor{}, fmt.Errorf("decode multicast subscriber monitor: required or matching field is missing")
	}
	result := multicast.Monitor{
		CurrentBandwidth: *value.CurrentBandwidth, JoinMessages: *value.JoinMessages,
		BandwidthExceeded: *value.BandwidthExceeded,
		Groups:            make([]multicast.ActiveGroup, 0, len(*value.Groups)),
	}
	for index, group := range *value.Groups {
		if group.Source == nil || group.Group == nil || group.Client == nil ||
			group.UNITagged == nil || group.UNIVLAN == nil || group.ANIVLAN == nil ||
			group.ProfileID == nil || group.ACLRowKey == nil || group.GEMPortID == nil ||
			group.ImputedBandwidth == nil || group.TimeSinceJoin == nil {
			return multicast.Monitor{}, fmt.Errorf("decode multicast subscriber monitor: group %d is incomplete", index)
		}
		source, err := netip.ParseAddr(*group.Source)
		if err != nil {
			return multicast.Monitor{}, fmt.Errorf("decode multicast subscriber monitor: group %d source: %w", index, err)
		}
		destination, err := netip.ParseAddr(*group.Group)
		if err != nil {
			return multicast.Monitor{}, fmt.Errorf("decode multicast subscriber monitor: group %d destination: %w", index, err)
		}
		var client netip.Addr
		if *group.Client != "" {
			client, err = netip.ParseAddr(*group.Client)
			if err != nil {
				return multicast.Monitor{}, fmt.Errorf("decode multicast subscriber monitor: group %d client: %w", index, err)
			}
		}
		active := multicast.ActiveGroup{
			Source: source, Group: destination, Client: client,
			UNIVLAN: multicast.VLAN{Tagged: *group.UNITagged, ID: *group.UNIVLAN},
			ANIVLAN: *group.ANIVLAN, ProfileID: *group.ProfileID,
			ACLRowKey: *group.ACLRowKey, GEMPortID: *group.GEMPortID,
			ImputedBandwidth: *group.ImputedBandwidth, TimeSinceJoin: *group.TimeSinceJoin,
		}
		if group.PreviewUntil != nil {
			active.PreviewUntil = *group.PreviewUntil
		}
		result.Groups = append(result.Groups, active)
	}
	return result, nil
}

func (c ExecController) AllowedPreviewStatus(entityID uint16) (multicast.AllowedPreviewSnapshot, error) {
	output, err := c.execute(controlRequest{
		Action: "multicast-preview-status", MulticastSubscriberID: &entityID,
	})
	if err != nil {
		return multicast.AllowedPreviewSnapshot{}, err
	}
	value, err := decodeMulticastState(output, entityID)
	if err != nil {
		return multicast.AllowedPreviewSnapshot{}, fmt.Errorf("decode multicast preview status: %w", err)
	}
	if value.MIBDataSync == nil || value.AllowedPreviews == nil {
		return multicast.AllowedPreviewSnapshot{}, fmt.Errorf(
			"decode multicast preview status: required field is missing")
	}
	result := multicast.AllowedPreviewSnapshot{MIBDataSync: *value.MIBDataSync,
		Timers: make([]multicast.AllowedPreviewTimer, 0, len(*value.AllowedPreviews))}
	seen := make(map[uint16]struct{}, len(*value.AllowedPreviews))
	for index, timer := range *value.AllowedPreviews {
		if timer.RowKey == nil || timer.Duration == nil || timer.TimeLeft == nil {
			return multicast.AllowedPreviewSnapshot{}, fmt.Errorf(
				"decode multicast preview status: timer %d is incomplete", index)
		}
		if *timer.RowKey > 1023 || (*timer.Duration == 0 && *timer.TimeLeft != 0) ||
			(*timer.Duration != 0 && *timer.TimeLeft > *timer.Duration) {
			return multicast.AllowedPreviewSnapshot{}, fmt.Errorf(
				"decode multicast preview status: timer %d is invalid", index)
		}
		if _, duplicate := seen[*timer.RowKey]; duplicate {
			return multicast.AllowedPreviewSnapshot{}, fmt.Errorf(
				"decode multicast preview status: duplicate row key %d", *timer.RowKey)
		}
		seen[*timer.RowKey] = struct{}{}
		result.Timers = append(result.Timers, multicast.AllowedPreviewTimer{
			RowKey: *timer.RowKey, Duration: *timer.Duration, TimeLeft: *timer.TimeLeft,
		})
	}
	return result, nil
}

func decodeMulticastState(output []byte, entityID uint16) (multicastStateResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var value multicastStateResponse
	if err := decoder.Decode(&value); err != nil {
		return multicastStateResponse{}, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return multicastStateResponse{}, fmt.Errorf("trailing JSON value")
		}
		return multicastStateResponse{}, err
	}
	if value.SubscriberID == nil || *value.SubscriberID != entityID {
		return multicastStateResponse{}, fmt.Errorf("required or matching subscriber ID is missing")
	}
	return value, nil
}

func (c ExecController) SynchronizeTime(value time.Time) error {
	_, err := c.execute(controlRequest{Action: "synchronize-time", UnixTime: value.Unix()})
	return err
}

func (c ExecController) Reboot(condition uint8) error {
	_, err := c.execute(controlRequest{Action: "reboot", RebootCondition: condition})
	return err
}

func (c ExecController) OpticalLineSupervision() (optical.Diagnostics, error) {
	output, err := c.execute(controlRequest{Action: "optical-line-supervision"})
	if err != nil {
		return optical.Diagnostics{}, err
	}
	type response struct {
		Temperature      *uint16 `json:"temperature"`
		SupplyVoltage    *uint16 `json:"supply_voltage"`
		LaserBiasCurrent *uint16 `json:"laser_bias_current"`
		TransmitPower    *uint16 `json:"transmit_power"`
		ReceivePower     *uint16 `json:"receive_power"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var value response
	if err := decoder.Decode(&value); err != nil {
		return optical.Diagnostics{}, fmt.Errorf("decode optical diagnostics: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return optical.Diagnostics{}, fmt.Errorf("decode optical diagnostics: trailing JSON value")
		}
		return optical.Diagnostics{}, fmt.Errorf("decode optical diagnostics: %w", err)
	}
	if value.Temperature == nil || value.SupplyVoltage == nil ||
		value.LaserBiasCurrent == nil || value.TransmitPower == nil ||
		value.ReceivePower == nil {
		return optical.Diagnostics{}, fmt.Errorf("decode optical diagnostics: required field is missing")
	}
	return (optical.Sample{
		Temperature:      *value.Temperature,
		SupplyVoltage:    *value.SupplyVoltage,
		LaserBiasCurrent: *value.LaserBiasCurrent,
		TransmitPower:    *value.TransmitPower,
		ReceivePower:     *value.ReceivePower,
	}).OMCI(), nil
}

func (c ExecController) execute(request controlRequest) ([]byte, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("platform control helper is empty")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultApplyTimeout
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode platform control: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, c.Path)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("platform control timed out after %s: %w", timeout, ctx.Err())
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			return nil, fmt.Errorf("platform control: %w", err)
		}
		return nil, fmt.Errorf("platform control: %w: %s", err, detail)
	}
	return stdout.Bytes(), nil
}

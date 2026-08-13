// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/multicast"
)

const (
	multicastSubscriberAllowedPreviewMask = 0x0200
	multicastMonitorCurrentBandwidthMask  = 0x4000
	multicastMonitorJoinCounterMask       = 0x2000
	multicastMonitorExceededCounterMask   = 0x1000
	multicastMonitorIPv4TableMask         = 0x0800
	multicastMonitorIPv6TableMask         = 0x0400
)

// PollMulticast commits timed class-310 row expiry even when the OLT is not
// issuing Get requests. No MIB data-sync increment or autonomous notification
// is generated for the ONU-owned time-left transition.
func (e *Engine) PollMulticast() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.multicastPreview == nil {
		return nil
	}
	for _, instance := range e.mib.Snapshot() {
		if instance.ClassID != me.MulticastSubscriberConfigInfoClassID {
			continue
		}
		if _, err := e.refreshAllowedPreviewLocked(instance.EntityID); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) getAllowedPreviewLocked(instance mib.Instance, mask uint16) (mib.Instance, error) {
	if e.multicastPreview == nil || mask&multicastSubscriberAllowedPreviewMask == 0 {
		return instance, nil
	}
	snapshot, err := e.refreshAllowedPreviewLocked(instance.EntityID)
	if err != nil {
		return mib.Instance{}, err
	}
	if snapshot == nil {
		return instance, nil
	}
	// Expiry may have replaced the committed instance after the initial Get.
	instance, err = e.mib.Get(instance.Key, mask)
	if err != nil {
		return mib.Instance{}, err
	}
	return mib.OverlayAllowedPreviewTimers(instance, mibAllowedPreviewTimers(snapshot.Timers))
}

func (e *Engine) refreshAllowedPreviewLocked(entityID uint16) (*multicast.AllowedPreviewSnapshot, error) {
	if e.multicastPreview == nil {
		return nil, nil
	}
	snapshot, err := e.multicastPreview.AllowedPreviewStatus(entityID)
	if err != nil {
		return nil, &mib.ResultError{Result: me.ProcessingError,
			Cause: fmt.Errorf("read multicast subscriber preview status %#x: %w", entityID, err)}
	}
	if snapshot.MIBDataSync != e.mib.DataSync() {
		return nil, nil
	}
	changed, err := e.mib.ExpireAllowedPreviewRows(mib.Key{
		ClassID: me.MulticastSubscriberConfigInfoClassID, EntityID: entityID,
	}, mibAllowedPreviewTimers(snapshot.Timers))
	if err != nil {
		return nil, &mib.ResultError{Result: me.ProcessingError,
			Cause: fmt.Errorf("expire multicast subscriber preview rows %#x: %w", entityID, err)}
	}
	if changed {
		e.tables = make(map[tableKey][]byte)
	}
	return &snapshot, nil
}

func mibAllowedPreviewTimers(timers []multicast.AllowedPreviewTimer) []mib.AllowedPreviewTimer {
	result := make([]mib.AllowedPreviewTimer, 0, len(timers))
	for _, timer := range timers {
		result = append(result, mib.AllowedPreviewTimer{
			RowKey: timer.RowKey, Duration: timer.Duration, TimeLeft: timer.TimeLeft,
		})
	}
	return result
}

func (e *Engine) getMulticastMonitorLocked(instance mib.Instance,
	mask uint16) (mib.Instance, error) {
	if e.multicast == nil {
		return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError,
			Cause: fmt.Errorf("multicast subscriber monitor backend is unavailable")}
	}
	monitor, err := e.multicast.SubscriberMonitor(instance.EntityID)
	if err != nil {
		return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError,
			Cause: fmt.Errorf("read multicast subscriber monitor %#x: %w", instance.EntityID, err)}
	}
	if mask&multicastMonitorCurrentBandwidthMask != 0 {
		instance.Attributes[me.MulticastSubscriberMonitor_CurrentMulticastBandwidth] =
			monitor.CurrentBandwidth
	}
	if mask&multicastMonitorJoinCounterMask != 0 {
		instance.Attributes[me.MulticastSubscriberMonitor_JoinMessagesCounter] = monitor.JoinMessages
	}
	if mask&multicastMonitorExceededCounterMask != 0 {
		instance.Attributes[me.MulticastSubscriberMonitor_BandwidthExceededCounter] =
			monitor.BandwidthExceeded
	}
	if mask&(multicastMonitorIPv4TableMask|multicastMonitorIPv6TableMask) != 0 {
		ipv4, ipv6, err := multicastMonitorTables(monitor.Groups)
		if err != nil {
			return mib.Instance{}, &mib.ResultError{Result: me.ProcessingError, Cause: err}
		}
		if mask&multicastMonitorIPv4TableMask != 0 {
			instance.Attributes[me.MulticastSubscriberMonitor_Ipv4ActiveGroupListTable] = ipv4
		}
		if mask&multicastMonitorIPv6TableMask != 0 {
			instance.Attributes[me.MulticastSubscriberMonitor_Ipv6ActiveGroupListTable] = ipv6
		}
	}
	return instance, nil
}

func multicastMonitorTables(groups []multicast.ActiveGroup) (me.TableRows, me.TableRows, error) {
	groups = append([]multicast.ActiveGroup(nil), groups...)
	sort.Slice(groups, func(i, j int) bool {
		if comparison := groups[i].Group.Compare(groups[j].Group); comparison != 0 {
			return comparison < 0
		}
		if comparison := groups[i].Source.Compare(groups[j].Source); comparison != 0 {
			return comparison < 0
		}
		return groups[i].Client.Compare(groups[j].Client) < 0
	})
	var ipv4, ipv6 []byte
	for _, group := range groups {
		if !group.Group.IsValid() || !group.Group.IsMulticast() || group.ANIVLAN > 4095 {
			return me.TableRows{}, me.TableRows{}, fmt.Errorf("multicast monitor contains invalid group %s/VLAN %d",
				group.Group, group.ANIVLAN)
		}
		if group.Group.Is4() {
			row, err := multicastMonitorIPv4Row(group)
			if err != nil {
				return me.TableRows{}, me.TableRows{}, err
			}
			ipv4 = append(ipv4, row...)
		} else {
			row, err := multicastMonitorIPv6Row(group)
			if err != nil {
				return me.TableRows{}, me.TableRows{}, err
			}
			ipv6 = append(ipv6, row...)
		}
	}
	return me.TableRows{NumRows: len(ipv4) / 24, Rows: ipv4},
		me.TableRows{NumRows: len(ipv6) / 58, Rows: ipv6}, nil
}

func multicastMonitorIPv4Row(group multicast.ActiveGroup) ([]byte, error) {
	row := make([]byte, 24)
	binary.BigEndian.PutUint16(row[0:2], group.ANIVLAN)
	if err := putMonitorIPv4(row[2:6], group.Source, "source"); err != nil {
		return nil, err
	}
	if err := putMonitorIPv4(row[6:10], group.Group, "group"); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(row[10:14], group.ImputedBandwidth)
	if err := putMonitorIPv4(row[14:18], group.Client, "client"); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(row[18:22], group.TimeSinceJoin)
	return row, nil
}

func putMonitorIPv4(destination []byte, address netip.Addr, name string) error {
	if !address.IsValid() || address.IsUnspecified() {
		return nil
	}
	if !address.Is4() {
		return fmt.Errorf("IPv4 multicast monitor has non-IPv4 %s %s", name, address)
	}
	value := address.As4()
	copy(destination, value[:])
	return nil
}

func multicastMonitorIPv6Row(group multicast.ActiveGroup) ([]byte, error) {
	row := make([]byte, 58)
	binary.BigEndian.PutUint16(row[0:2], group.ANIVLAN)
	if err := putMonitorIPv6(row[2:18], group.Source, "source"); err != nil {
		return nil, err
	}
	if err := putMonitorIPv6(row[18:34], group.Group, "group"); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(row[34:38], group.ImputedBandwidth)
	if err := putMonitorIPv6(row[38:54], group.Client, "client"); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(row[54:58], group.TimeSinceJoin)
	return row, nil
}

func putMonitorIPv6(destination []byte, address netip.Addr, name string) error {
	if !address.IsValid() || address.IsUnspecified() {
		return nil
	}
	if address.Is4() {
		value := address.As4()
		copy(destination[12:], value[:])
		return nil
	}
	if !address.Is6() {
		return fmt.Errorf("IPv6 multicast monitor has invalid %s %s", name, address)
	}
	value := address.As16()
	copy(destination, value[:])
	return nil
}

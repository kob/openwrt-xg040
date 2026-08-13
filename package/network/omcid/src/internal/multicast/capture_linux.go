// SPDX-License-Identifier: Apache-2.0

package multicast

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// CaptureMembership receives ingress Ethernet frames before the tc guard drops
// IGMP/MLD reports. VLAN metadata stripped by hardware offload is restored so
// G.988 matching and transparent tag control see the wire representation.
func CaptureMembership(ctx context.Context, interfaceName string,
	handle func(MembershipMessage) error) error {
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL), Ifindex: device.Index,
	}); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		return err
	}
	data := make([]byte, 65536)
	control := make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(unix.TpacketAuxdata{}))))
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(poll, 1000)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if count == 0 {
			continue
		}
		length, controlLength, _, address, err := unix.Recvmsg(fd, data, control, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		link, ok := address.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		frame := append([]byte(nil), data[:length]...)
		frame, err = restoreCapturedVLAN(frame, control[:controlLength])
		if err != nil {
			return err
		}
		message, err := ParseMembershipFrame(frame)
		if errors.Is(err, ErrNotMembership) {
			continue
		}
		if err != nil {
			continue
		}
		message.Downstream = link.Pkttype == unix.PACKET_OUTGOING
		if err := handle(message); err != nil {
			return err
		}
	}
}

func restoreCapturedVLAN(frame, control []byte) ([]byte, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return nil, fmt.Errorf("parse packet auxiliary data: %w", err)
	}
	for _, message := range messages {
		if message.Header.Level != unix.SOL_PACKET || message.Header.Type != unix.PACKET_AUXDATA ||
			len(message.Data) < int(unsafe.Sizeof(unix.TpacketAuxdata{})) {
			continue
		}
		auxiliary := *(*unix.TpacketAuxdata)(unsafe.Pointer(&message.Data[0]))
		if auxiliary.Status&unix.TP_STATUS_VLAN_VALID == 0 {
			continue
		}
		if len(frame) < 14 {
			return nil, fmt.Errorf("captured VLAN frame is truncated")
		}
		wireType := binary.BigEndian.Uint16(frame[12:14])
		if wireType == 0x8100 || wireType == 0x88a8 || wireType == 0x9100 {
			return frame, nil
		}
		typeValue := uint16(0x8100)
		if auxiliary.Status&unix.TP_STATUS_VLAN_TPID_VALID != 0 && auxiliary.Vlan_tpid != 0 {
			typeValue = auxiliary.Vlan_tpid
		}
		restored := make([]byte, len(frame)+4)
		copy(restored[:12], frame[:12])
		binary.BigEndian.PutUint16(restored[12:14], typeValue)
		binary.BigEndian.PutUint16(restored[14:16], auxiliary.Vlan_tci)
		copy(restored[16:], frame[12:])
		return restored, nil
	}
	return frame, nil
}

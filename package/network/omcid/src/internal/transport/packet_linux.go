// SPDX-License-Identifier: Apache-2.0
//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const pollIntervalMS = 250

type PacketConn struct {
	fd      int
	ifindex int
	close   sync.Once
}

func OpenPacket(interfaceName string) (*PacketConn, error) {
	ifc, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve OMCI interface %q: %w", interfaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("open OMCI packet socket: %w", err)
	}

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifc.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind OMCI packet socket to %q: %w", interfaceName, err)
	}
	// The receive path also checks sll_pkttype for kernels that do not support
	// PACKET_IGNORE_OUTGOING.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)

	return &PacketConn{fd: fd, ifindex: ifc.Index}, nil
}

func (c *PacketConn) ReadFrame(ctx context.Context) (Frame, error) {
	buf := make([]byte, MaxFrameSize+1)

	for {
		if err := ctx.Err(); err != nil {
			return Frame{}, err
		}

		poll := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, pollIntervalMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return Frame{}, fmt.Errorf("poll OMCI packet socket: %w", err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return Frame{}, syscall.EBADF
		}

		var source unix.Sockaddr
		n, source, err = unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return Frame{}, fmt.Errorf("receive OMCI frame: %w", err)
		}
		if n == 0 {
			continue
		}
		if link, ok := source.(*unix.SockaddrLinklayer); ok && link.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if n > MaxFrameSize {
			return Frame{}, fmt.Errorf("invalid OMCI frame length %d", n)
		}
		return Frame{Contents: append([]byte(nil), buf[:n]...)}, nil
	}
}

func (c *PacketConn) WriteFrame(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(frame) < 4 || len(frame) > MaxFrameSize {
		return fmt.Errorf("invalid OMCI frame length %d", len(frame))
	}

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  c.ifindex,
	}
	if err := unix.Sendto(c.fd, frame, 0, addr); err != nil {
		return fmt.Errorf("send OMCI frame: %w", err)
	}
	return nil
}

func (c *PacketConn) Close() error {
	var err error
	c.close.Do(func() {
		err = unix.Close(c.fd)
	})
	return err
}

func (c *PacketConn) Capabilities() Capabilities {
	return Capabilities{}
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

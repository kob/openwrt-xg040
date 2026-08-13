// SPDX-License-Identifier: Apache-2.0
//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// AIROHA_XGS_OMCC_GET_INFO is _IOR('X', 0, __u32).
const deviceGetInfoIOCTL = 0x80045800

type DeviceConn struct {
	fd           int
	capabilities Capabilities
	close        sync.Once
}

func OpenDevice(path string) (Conn, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open secure OMCC device %q: %w", path, err)
	}
	closeOnError := func(err error) (Conn, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return closeOnError(fmt.Errorf("stat secure OMCC device %q: %w", path, err))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return closeOnError(fmt.Errorf("secure OMCC path %q is not a character device", path))
	}
	info, err := unix.IoctlGetUint32(fd, deviceGetInfoIOCTL)
	if err != nil {
		return closeOnError(fmt.Errorf("query secure OMCC device %q: %w", path, err))
	}
	capabilities, err := parseDeviceInfo(info)
	if err != nil {
		return closeOnError(fmt.Errorf("query secure OMCC device %q: %w", path, err))
	}
	return &DeviceConn{fd: fd, capabilities: capabilities}, nil
}

func (c *DeviceConn) ReadFrame(ctx context.Context) (Frame, error) {
	record := make([]byte, deviceHeaderSize+MaxFrameSize)
	for {
		if err := waitDevice(ctx, c.fd, unix.POLLIN); err != nil {
			return Frame{}, err
		}
		n, err := unix.Read(c.fd, record)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return Frame{}, fmt.Errorf("read secure OMCC device: %w", err)
		}
		if n == 0 {
			return Frame{}, io.EOF
		}
		frame, err := decodeDeviceRX(record[:n])
		if err != nil {
			return Frame{}, err
		}
		return frame, nil
	}
}

func (c *DeviceConn) WriteFrame(ctx context.Context, frame []byte) error {
	record, err := encodeDeviceTX(frame)
	if err != nil {
		return err
	}
	for {
		if err := waitDevice(ctx, c.fd, unix.POLLOUT); err != nil {
			return err
		}
		n, err := unix.Write(c.fd, record)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return fmt.Errorf("write secure OMCC device: %w", err)
		}
		if n != len(record) {
			return fmt.Errorf("write secure OMCC device: %w (%d of %d bytes)", io.ErrShortWrite, n, len(record))
		}
		return nil
	}
}

func (c *DeviceConn) Capabilities() Capabilities {
	return c.capabilities
}

func (c *DeviceConn) Close() error {
	var err error
	c.close.Do(func() {
		err = unix.Close(c.fd)
	})
	return err
}

func waitDevice(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(poll, pollIntervalMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll secure OMCC device: %w", err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return syscall.EBADF
		}
		if poll[0].Revents&events != 0 {
			return nil
		}
	}
}

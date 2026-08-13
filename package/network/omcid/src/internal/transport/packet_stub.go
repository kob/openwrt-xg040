// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package transport

import "fmt"

func OpenPacket(interfaceName string) (Conn, error) {
	return nil, fmt.Errorf("AF_PACKET OMCI transport is unavailable on this platform: %s", interfaceName)
}

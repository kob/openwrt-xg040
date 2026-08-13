// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package transport

import "fmt"

func OpenDevice(path string) (Conn, error) {
	return nil, fmt.Errorf("secure OMCC device transport is unavailable on this platform: %s", path)
}

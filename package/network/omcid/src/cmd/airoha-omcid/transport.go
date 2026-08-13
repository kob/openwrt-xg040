// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/xg2010g/airoha-omci/internal/transport"
)

func openTransport(opts options) (transport.Conn, error) {
	switch opts.transportBackend {
	case "packet":
		return transport.OpenPacket(opts.interfaceName)
	case "device":
		return transport.OpenDevice(opts.devicePath)
	default:
		return nil, fmt.Errorf("unsupported OMCC transport %q", opts.transportBackend)
	}
}

// SPDX-License-Identifier: Apache-2.0

package transport

import "context"

const MaxFrameSize = 1980

type Frame struct {
	Contents    []byte
	MICVerified bool
}

type Capabilities struct {
	VerifiedDownstreamMIC bool
	SignedUpstreamMIC     bool
}

func (c Capabilities) SecureOMCC() bool {
	return c.VerifiedDownstreamMIC && c.SignedUpstreamMIC
}

// Conn carries bare OMCI frames. Implementations must not add an Ethernet
// header. MICVerified is trusted only when Capabilities reports secure OMCC.
type Conn interface {
	ReadFrame(context.Context) (Frame, error)
	WriteFrame(context.Context, []byte) error
	Capabilities() Capabilities
	Close() error
}

// SPDX-License-Identifier: Apache-2.0

// Package software defines the narrow platform boundary used by the OMCI
// software image state machine. The protocol engine never receives a command
// path or shell fragment from the OLT.
package software

import "io"

type Image struct {
	EntityID    uint16
	Version     string
	ProductCode string
	ImageHash   [16]byte
	Committed   bool
	Active      bool
	Valid       bool
}

type Metadata struct {
	Version     string `json:"version"`
	ProductCode string `json:"product_code"`
}

// Download is an inactive-image staging transaction. Finish must make the
// fully written image available for a later Activate call, while Abort must
// discard any partial image.
type Download interface {
	io.Writer
	Finish() (Metadata, error)
	Abort() error
}

// Transaction represents a prepared software-slot mutation. Commit makes the
// mutation durable only after the OMCI MIB candidate has been persisted;
// Abort restores the pre-command slot state.
type Transaction interface {
	Commit() error
	Abort() error
}

type Controller interface {
	Images() ([]Image, error)
	Start(entityID uint16, imageSize uint32) (Download, error)
	PrepareActivate(entityID uint16, flags uint8) (Transaction, error)
	PrepareCommit(entityID uint16) (Transaction, error)
}

// SPDX-License-Identifier: Apache-2.0

package onu3

import (
	"encoding/binary"
	"time"
)

const (
	SnapshotCapacity = 16
	RecordSize       = 25
	FormatVersion    = 1

	TriggerOLTSnap = 1

	FlagExtendedOMCI = 1 << 0
)

// Record is the XG2010G vendor-specific ONU3-G status snapshot payload.
type Record struct {
	Trigger      uint8
	TakenAt      time.Time
	MIBDataSync  uint8
	MIBEntries   uint16
	ActiveAlarms uint16
	ExtendedOMCI bool
}

func (r Record) Encode() [RecordSize]byte {
	var encoded [RecordSize]byte
	encoded[0] = FormatVersion
	encoded[1] = r.Trigger
	binary.BigEndian.PutUint64(encoded[2:10], uint64(r.TakenAt.UTC().Unix()))
	encoded[10] = r.MIBDataSync
	binary.BigEndian.PutUint16(encoded[11:13], r.MIBEntries)
	binary.BigEndian.PutUint16(encoded[13:15], r.ActiveAlarms)
	if r.ExtendedOMCI {
		encoded[15] |= FlagExtendedOMCI
	}
	return encoded
}

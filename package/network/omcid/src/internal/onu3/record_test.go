// SPDX-License-Identifier: Apache-2.0

package onu3

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestRecordEncoding(t *testing.T) {
	takenAt := time.Date(2026, time.August, 11, 4, 5, 6, 0, time.FixedZone("test", 8*60*60))
	encoded := (Record{
		Trigger: TriggerOLTSnap, TakenAt: takenAt, MIBDataSync: 7,
		MIBEntries: 123, ActiveAlarms: 4, ExtendedOMCI: true,
	}).Encode()

	if len(encoded) != RecordSize || encoded[0] != FormatVersion ||
		encoded[1] != TriggerOLTSnap ||
		binary.BigEndian.Uint64(encoded[2:10]) != uint64(takenAt.Unix()) ||
		encoded[10] != 7 || binary.BigEndian.Uint16(encoded[11:13]) != 123 ||
		binary.BigEndian.Uint16(encoded[13:15]) != 4 ||
		encoded[15] != FlagExtendedOMCI {
		t.Fatalf("encoded ONU3-G record = %x", encoded)
	}
	for index, value := range encoded[16:] {
		if value != 0 {
			t.Fatalf("reserved byte %d = %#x, want zero", index+16, value)
		}
	}
}

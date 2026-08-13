// SPDX-License-Identifier: Apache-2.0

package vlan

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseClassicRule(t *testing.T) {
	row := make([]byte, ClassicRowSize)
	binary.BigEndian.PutUint32(row[0:4], filterWord(15, 4096, 0))
	binary.BigEndian.PutUint32(row[4:8], filterWord(5, 100, 4)|uint32(2)<<4|3)
	binary.BigEndian.PutUint32(row[8:12], uint32(1)<<30|treatmentWord(15, 0, 0))
	binary.BigEndian.PutUint32(row[12:16], treatmentWord(5, 200, 4))

	rule, err := ParseRow(row, false)
	if err != nil {
		t.Fatalf("ParseRow() error = %v", err)
	}
	if rule.Direction != 0 || rule.FilterInner.Priority != 5 || rule.FilterInner.VID != 100 ||
		rule.FilterInner.TPIDDEI != 4 || rule.ExtendedCriteria != 2 || rule.EtherType != 3 ||
		rule.TagsToRemove != 1 || rule.TreatmentInner.Priority != 5 ||
		rule.TreatmentInner.VID != 200 || rule.TreatmentInner.TPIDDEI != 4 {
		t.Fatalf("decoded rule = %#v", rule)
	}
}

func TestParseEnhancedRule(t *testing.T) {
	row := make([]byte, EnhancedRowSize)
	binary.BigEndian.PutUint32(row[0:4], uint32(2)<<28|0x1234)
	binary.BigEndian.PutUint32(row[4:8], filterWord(8, 4096, 5))
	binary.BigEndian.PutUint32(row[8:12], filterWord(15, 4096, 0))
	binary.BigEndian.PutUint32(row[12:16], uint32(3)<<30|treatmentWord(15, 0, 0))
	binary.BigEndian.PutUint32(row[16:20], treatmentWord(15, 0, 0))

	rule, err := ParseRow(row, true)
	if err != nil {
		t.Fatalf("ParseRow() error = %v", err)
	}
	if rule.RowKey != 0x1234 || rule.Direction != 2 || rule.TagsToRemove != 3 {
		t.Fatalf("decoded rule = %#v", rule)
	}
}

func TestParseRowsAssignsStableOrder(t *testing.T) {
	rows := make([]byte, 2*ClassicRowSize)
	for offset := 0; offset < len(rows); offset += ClassicRowSize {
		binary.BigEndian.PutUint32(rows[offset:offset+4], filterWord(15, 4096, 0))
		binary.BigEndian.PutUint32(rows[offset+4:offset+8], filterWord(15, 4096, 0))
		binary.BigEndian.PutUint32(rows[offset+8:offset+12], treatmentWord(15, 0, 0))
		binary.BigEndian.PutUint32(rows[offset+12:offset+16], treatmentWord(15, 0, 0))
	}
	rules, err := ParseRows(rows, false)
	if err != nil || len(rules) != 2 || rules[0].Order != 0 || rules[1].Order != 1 {
		t.Fatalf("ParseRows() = %#v, %v", rules, err)
	}
}

func TestParseRejectsReservedFields(t *testing.T) {
	valid := make([]byte, ClassicRowSize)
	binary.BigEndian.PutUint32(valid[0:4], filterWord(15, 4096, 0))
	binary.BigEndian.PutUint32(valid[4:8], filterWord(15, 4096, 0))
	binary.BigEndian.PutUint32(valid[8:12], treatmentWord(15, 0, 0))
	binary.BigEndian.PutUint32(valid[12:16], treatmentWord(15, 0, 0))

	tests := []struct {
		name string
		edit func([]byte)
		want string
	}{
		{name: "padding", edit: func(row []byte) { row[3] = 1 }, want: "reserved bits"},
		{name: "priority", edit: func(row []byte) { row[0] = 0x90 }, want: "priority 9"},
		{name: "filter VID", edit: func(row []byte) { binary.BigEndian.PutUint32(row[0:4], filterWord(15, 4095, 0)) }, want: "VID 4095"},
		{name: "ethertype", edit: func(row []byte) { row[7] = 6 }, want: "Ethertype 6"},
		{name: "criteria", edit: func(row []byte) { row[7] = 0x30 }, want: "criteria 3"},
		{name: "treatment TPID", edit: func(row []byte) { row[15] = 5 }, want: "TPID/DEI 5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := append([]byte(nil), valid...)
			test.edit(row)
			_, err := ParseRow(row, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseRow() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseEnhancedRejectsControlDirectionAndReservedWords(t *testing.T) {
	base := make([]byte, EnhancedRowSize)
	binary.BigEndian.PutUint32(base[4:8], filterWord(15, 4096, 0))
	binary.BigEndian.PutUint32(base[8:12], filterWord(15, 4096, 0))
	binary.BigEndian.PutUint32(base[12:16], treatmentWord(15, 0, 0))
	binary.BigEndian.PutUint32(base[16:20], treatmentWord(15, 0, 0))
	tests := []struct {
		name string
		edit func([]byte)
	}{
		{name: "control", edit: func(row []byte) { row[0] = 0x40 }},
		{name: "direction", edit: func(row []byte) { row[0] = 0x30 }},
		{name: "header padding", edit: func(row []byte) { row[1] = 1 }},
		{name: "word 6", edit: func(row []byte) { row[23] = 1 }},
		{name: "word 7", edit: func(row []byte) { row[27] = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := append([]byte(nil), base...)
			test.edit(row)
			if _, err := ParseRow(row, true); err == nil {
				t.Fatal("ParseRow() succeeded, want error")
			}
		})
	}
}

func TestDecodeDSCPMappingAcrossByteBoundaries(t *testing.T) {
	encoded := make([]byte, 24)
	want := [64]uint8{}
	for index := range want {
		want[index] = uint8(index % 8)
		for bit := 0; bit < 3; bit++ {
			position := index*3 + bit
			encoded[position/8] |= (want[index] >> (2 - bit) & 1) << (7 - position%8)
		}
	}
	got, err := DecodeDSCPMapping(encoded)
	if err != nil || got != want {
		t.Fatalf("DecodeDSCPMapping() = %v, %v", got, err)
	}
}

func filterWord(priority uint8, vid uint16, tpid uint8) uint32 {
	return uint32(priority)<<28 | uint32(vid)<<15 | uint32(tpid)<<12
}

func treatmentWord(priority uint8, vid uint16, tpid uint8) uint32 {
	return uint32(priority)<<16 | uint32(vid)<<3 | uint32(tpid)
}

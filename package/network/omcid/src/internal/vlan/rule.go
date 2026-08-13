// SPDX-License-Identifier: Apache-2.0

// Package vlan decodes the G.988 extended VLAN classification tables.
package vlan

import (
	"encoding/binary"
	"fmt"
)

const (
	ClassicRowSize  = 16
	EnhancedRowSize = 28
)

type TagFilter struct {
	Priority uint8  `json:"priority"`
	VID      uint16 `json:"vid"`
	TPIDDEI  uint8  `json:"tpid_dei"`
}

type TagTreatment struct {
	Priority uint8  `json:"priority"`
	VID      uint16 `json:"vid"`
	TPIDDEI  uint8  `json:"tpid_dei"`
}

// Rule is one normalized row from either G.988 Figure 9.3.13-1 or 9.3.13-2.
// Stored enhanced rows always have SetControl zero.
type Rule struct {
	Order            uint16       `json:"order"`
	RowKey           uint16       `json:"row_key"`
	Direction        uint8        `json:"direction"`
	FilterOuter      TagFilter    `json:"filter_outer"`
	FilterInner      TagFilter    `json:"filter_inner"`
	EtherType        uint8        `json:"ethertype"`
	ExtendedCriteria uint8        `json:"extended_criteria"`
	TagsToRemove     uint8        `json:"tags_to_remove"`
	TreatmentOuter   TagTreatment `json:"treatment_outer"`
	TreatmentInner   TagTreatment `json:"treatment_inner"`
}

func ParseRows(encoded []byte, enhanced bool) ([]Rule, error) {
	rowSize := ClassicRowSize
	if enhanced {
		rowSize = EnhancedRowSize
	}
	if len(encoded)%rowSize != 0 {
		return nil, fmt.Errorf("VLAN table length %d is not a multiple of row size %d", len(encoded), rowSize)
	}
	rules := make([]Rule, 0, len(encoded)/rowSize)
	for offset := 0; offset < len(encoded); offset += rowSize {
		rule, err := ParseRow(encoded[offset:offset+rowSize], enhanced)
		if err != nil {
			return nil, fmt.Errorf("VLAN rule %d: %w", offset/rowSize, err)
		}
		rule.Order = uint16(offset / rowSize)
		rules = append(rules, rule)
	}
	return rules, nil
}

func ParseRow(encoded []byte, enhanced bool) (Rule, error) {
	rowSize := ClassicRowSize
	wordOffset := 0
	rule := Rule{}
	if enhanced {
		rowSize = EnhancedRowSize
		wordOffset = 4
	}
	if len(encoded) != rowSize {
		return Rule{}, fmt.Errorf("row length is %d, want %d", len(encoded), rowSize)
	}
	if enhanced {
		header := binary.BigEndian.Uint32(encoded[:4])
		if control := uint8(header >> 30); control != 0 {
			return Rule{}, fmt.Errorf("stored Set control is %d, want 0", control)
		}
		rule.Direction = uint8(header>>28) & 0x03
		if rule.Direction == 3 {
			return Rule{}, fmt.Errorf("direction 3 is reserved")
		}
		if header&0x0fff0000 != 0 {
			return Rule{}, fmt.Errorf("header reserved bits are non-zero")
		}
		rule.RowKey = uint16(header)
		if binary.BigEndian.Uint32(encoded[20:24]) != 0 || binary.BigEndian.Uint32(encoded[24:28]) != 0 {
			return Rule{}, fmt.Errorf("reserved words are non-zero")
		}
	}

	outerFilter := binary.BigEndian.Uint32(encoded[wordOffset : wordOffset+4])
	innerFilter := binary.BigEndian.Uint32(encoded[wordOffset+4 : wordOffset+8])
	outerTreatment := binary.BigEndian.Uint32(encoded[wordOffset+8 : wordOffset+12])
	innerTreatment := binary.BigEndian.Uint32(encoded[wordOffset+12 : wordOffset+16])
	if outerFilter&0x00000fff != 0 {
		return Rule{}, fmt.Errorf("outer filter reserved bits are non-zero")
	}
	if outerTreatment&0x3ff00000 != 0 {
		return Rule{}, fmt.Errorf("outer treatment reserved bits are non-zero")
	}
	if innerTreatment&0xfff00000 != 0 {
		return Rule{}, fmt.Errorf("inner treatment reserved bits are non-zero")
	}

	rule.FilterOuter = decodeFilter(outerFilter)
	rule.FilterInner = decodeFilter(innerFilter)
	rule.ExtendedCriteria = uint8(innerFilter>>4) & 0xff
	rule.EtherType = uint8(innerFilter) & 0x0f
	rule.TagsToRemove = uint8(outerTreatment >> 30)
	rule.TreatmentOuter = decodeTreatment(outerTreatment)
	rule.TreatmentInner = decodeTreatment(innerTreatment)

	if err := validateFilter("outer", rule.FilterOuter); err != nil {
		return Rule{}, err
	}
	if err := validateFilter("inner", rule.FilterInner); err != nil {
		return Rule{}, err
	}
	if rule.EtherType > 5 {
		return Rule{}, fmt.Errorf("filter Ethertype %d is reserved", rule.EtherType)
	}
	if rule.ExtendedCriteria > 2 {
		return Rule{}, fmt.Errorf("extended criteria %d is reserved", rule.ExtendedCriteria)
	}
	if err := validateTreatment("outer", rule.TreatmentOuter); err != nil {
		return Rule{}, err
	}
	if err := validateTreatment("inner", rule.TreatmentInner); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func DecodeDSCPMapping(encoded []byte) ([64]uint8, error) {
	var mapping [64]uint8
	if len(encoded) != 24 {
		return mapping, fmt.Errorf("DSCP mapping length is %d, want 24", len(encoded))
	}
	for dscp := range mapping {
		bit := dscp * 3
		for index := 0; index < 3; index++ {
			position := bit + index
			mapping[dscp] = mapping[dscp]<<1 | (encoded[position/8] >> (7 - position%8) & 1)
		}
	}
	return mapping, nil
}

func decodeFilter(word uint32) TagFilter {
	return TagFilter{
		Priority: uint8(word >> 28),
		VID:      uint16(word>>15) & 0x1fff,
		TPIDDEI:  uint8(word>>12) & 0x07,
	}
}

func decodeTreatment(word uint32) TagTreatment {
	return TagTreatment{
		Priority: uint8(word>>16) & 0x0f,
		VID:      uint16(word>>3) & 0x1fff,
		TPIDDEI:  uint8(word) & 0x07,
	}
}

func validateFilter(name string, filter TagFilter) error {
	if filter.Priority > 8 && filter.Priority != 14 && filter.Priority != 15 {
		return fmt.Errorf("filter %s priority %d is reserved", name, filter.Priority)
	}
	if filter.VID == 4095 || filter.VID > 4096 {
		return fmt.Errorf("filter %s VID %d is reserved", name, filter.VID)
	}
	if filter.TPIDDEI != 0 && filter.TPIDDEI < 4 {
		return fmt.Errorf("filter %s TPID/DEI %d is reserved", name, filter.TPIDDEI)
	}
	return nil
}

func validateTreatment(name string, treatment TagTreatment) error {
	if treatment.Priority > 10 && treatment.Priority != 15 {
		return fmt.Errorf("treatment %s priority %d is reserved", name, treatment.Priority)
	}
	if treatment.VID == 4095 || treatment.VID > 4097 {
		return fmt.Errorf("treatment %s VID %d is reserved", name, treatment.VID)
	}
	if treatment.TPIDDEI == 5 {
		return fmt.Errorf("treatment %s TPID/DEI 5 is reserved", name)
	}
	return nil
}

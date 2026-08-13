// SPDX-License-Identifier: Apache-2.0

// Package pon defines values that must remain isolated between PON protocol
// families. It intentionally contains no hardware policy.
package pon

import "fmt"

type Mode string

const (
	GPON   Mode = "gpon"
	XGSPON Mode = "xgspon"
)

func ParseMode(value string) (Mode, error) {
	mode := Mode(value)
	if err := mode.Validate(); err != nil {
		return "", err
	}
	return mode, nil
}

func (m Mode) Validate() error {
	switch m {
	case GPON, XGSPON:
		return nil
	default:
		return fmt.Errorf("unsupported PON mode %q", m)
	}
}

// StateDomain binds persistent MIB documents to both this board model and one
// PON protocol family. A serial number alone cannot prevent GPON/XGS state reuse.
func (m Mode) StateDomain() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	return "xg2010g:" + string(m), nil
}

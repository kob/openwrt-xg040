// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/binary"
	"testing"
)

func TestParseDeviceInfoRequiresExactSecureABI(t *testing.T) {
	valid := uint32(deviceABIVersion | deviceInfoVerifiedDownstream | deviceInfoSignedUpstream)
	capabilities, err := parseDeviceInfo(valid)
	if err != nil || !capabilities.SecureOMCC() {
		t.Fatalf("parseDeviceInfo(valid) capabilities=%+v error=%v", capabilities, err)
	}
	for _, invalid := range []uint32{
		0,
		deviceABIVersion | deviceInfoVerifiedDownstream,
		deviceABIVersion | deviceInfoSignedUpstream,
		2 | deviceInfoVerifiedDownstream | deviceInfoSignedUpstream,
		valid | 1<<31,
	} {
		if _, err := parseDeviceInfo(invalid); err == nil {
			t.Fatalf("parseDeviceInfo(%#x) error=nil", invalid)
		}
	}
}

func TestDeviceRecordRoundTripAndTrustValidation(t *testing.T) {
	payload := []byte{0x80, 0x01, 0x29, 0x0a, 0xaa}
	tx, err := encodeDeviceTX(payload)
	if err != nil {
		t.Fatalf("encodeDeviceTX() error=%v", err)
	}
	if tx[5] != deviceDirectionTX || binary.BigEndian.Uint16(tx[8:10]) != uint16(len(payload)) {
		t.Fatalf("encoded TX header=%x", tx[:deviceHeaderSize])
	}
	rx := append([]byte(nil), tx...)
	rx[5] = deviceDirectionRX
	binary.BigEndian.PutUint16(rx[6:8], deviceFlagMICVerified|deviceFlagTrailerStripped)
	frame, err := decodeDeviceRX(rx)
	if err != nil {
		t.Fatalf("decodeDeviceRX() error=%v", err)
	}
	if !frame.MICVerified || string(frame.Contents) != string(payload) {
		t.Fatalf("decoded frame=%+v", frame)
	}
	rx[6], rx[7] = 0, 0
	if _, err := decodeDeviceRX(rx); err == nil {
		t.Fatal("decodeDeviceRX(unverified) error=nil")
	}
}

func TestDeviceRecordRejectsMalformedHeaders(t *testing.T) {
	payload := []byte{0, 1, 2, 0x0a}
	record, err := encodeDeviceTX(payload)
	if err != nil {
		t.Fatal(err)
	}
	record[5] = deviceDirectionRX
	binary.BigEndian.PutUint16(record[6:8], deviceFlagMICVerified|deviceFlagTrailerStripped)

	tests := [][]byte{
		record[:deviceHeaderSize-1],
		append([]byte(nil), record...),
		append([]byte(nil), record...),
		append([]byte(nil), record...),
		append([]byte(nil), record...),
	}
	tests[1][0] = 0
	tests[2][4] = 2
	tests[3][10] = 1
	binary.BigEndian.PutUint16(tests[4][8:10], uint16(len(payload)+1))
	for index, invalid := range tests {
		if _, err := decodeDeviceRX(invalid); err == nil {
			t.Fatalf("decodeDeviceRX(invalid %d) error=nil", index)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/binary"
	"fmt"
)

const (
	deviceABIVersion = 1
	deviceMagic      = 0x584f4d43 // "XOMC"
	deviceHeaderSize = 12

	deviceDirectionRX = 1
	deviceDirectionTX = 2

	deviceFlagMICVerified     = 1 << 0
	deviceFlagTrailerStripped = 1 << 1

	deviceInfoVersionMask        = 0xff
	deviceInfoVerifiedDownstream = 1 << 8
	deviceInfoSignedUpstream     = 1 << 9
	deviceInfoAllowed            = deviceInfoVersionMask |
		deviceInfoVerifiedDownstream | deviceInfoSignedUpstream
)

func parseDeviceInfo(info uint32) (Capabilities, error) {
	version := info & deviceInfoVersionMask
	if version != deviceABIVersion {
		return Capabilities{}, fmt.Errorf("unsupported secure OMCC ABI version %d", version)
	}
	if info & ^uint32(deviceInfoAllowed) != 0 {
		return Capabilities{}, fmt.Errorf("secure OMCC ABI reports unknown capabilities %#x", info)
	}
	capabilities := Capabilities{
		VerifiedDownstreamMIC: info&deviceInfoVerifiedDownstream != 0,
		SignedUpstreamMIC:     info&deviceInfoSignedUpstream != 0,
	}
	if !capabilities.SecureOMCC() {
		return Capabilities{}, fmt.Errorf("secure OMCC device lacks required capabilities %#x", info)
	}
	return capabilities, nil
}

func decodeDeviceRX(record []byte) (Frame, error) {
	if len(record) < deviceHeaderSize {
		return Frame{}, fmt.Errorf("short secure OMCC record: %d bytes", len(record))
	}
	if binary.BigEndian.Uint32(record[0:4]) != deviceMagic {
		return Frame{}, fmt.Errorf("invalid secure OMCC record magic")
	}
	if record[4] != deviceABIVersion {
		return Frame{}, fmt.Errorf("unsupported secure OMCC record version %d", record[4])
	}
	if record[5] != deviceDirectionRX {
		return Frame{}, fmt.Errorf("invalid secure OMCC receive direction %d", record[5])
	}
	flags := binary.BigEndian.Uint16(record[6:8])
	wantFlags := uint16(deviceFlagMICVerified | deviceFlagTrailerStripped)
	if flags != wantFlags {
		return Frame{}, fmt.Errorf("untrusted secure OMCC receive flags %#x", flags)
	}
	length := int(binary.BigEndian.Uint16(record[8:10]))
	if binary.BigEndian.Uint16(record[10:12]) != 0 {
		return Frame{}, fmt.Errorf("secure OMCC record reserved field is non-zero")
	}
	if length < 4 || length > MaxFrameSize || len(record) != deviceHeaderSize+length {
		return Frame{}, fmt.Errorf("invalid secure OMCC frame length %d in %d-byte record", length, len(record))
	}
	return Frame{
		Contents:    append([]byte(nil), record[deviceHeaderSize:]...),
		MICVerified: true,
	}, nil
}

func encodeDeviceTX(frame []byte) ([]byte, error) {
	if len(frame) < 4 || len(frame) > MaxFrameSize {
		return nil, fmt.Errorf("invalid OMCI frame length %d", len(frame))
	}
	record := make([]byte, deviceHeaderSize+len(frame))
	binary.BigEndian.PutUint32(record[0:4], deviceMagic)
	record[4] = deviceABIVersion
	record[5] = deviceDirectionTX
	binary.BigEndian.PutUint16(record[8:10], uint16(len(frame)))
	copy(record[deviceHeaderSize:], frame)
	return record, nil
}

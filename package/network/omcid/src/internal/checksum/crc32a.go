// SPDX-License-Identifier: Apache-2.0

// Package checksum contains integrity algorithms required by G.988 that are
// not provided by Go's standard hash packages.
package checksum

const (
	crc32APolynomial = uint32(0x04c11db7)
	CRC32AInitial    = uint32(0xffffffff)
)

// UpdateCRC32A updates the non-reflected CRC-32/ITU-I.363.5 accumulator used
// for OMCI software downloads. Call SumCRC32A to apply the final XOR.
func UpdateCRC32A(crc uint32, value []byte) uint32 {
	for _, octet := range value {
		crc ^= uint32(octet) << 24
		for bit := 0; bit < 8; bit++ {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ crc32APolynomial
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func SumCRC32A(crc uint32) uint32 {
	return crc ^ 0xffffffff
}

func CRC32A(value []byte) uint32 {
	return SumCRC32A(UpdateCRC32A(CRC32AInitial, value))
}

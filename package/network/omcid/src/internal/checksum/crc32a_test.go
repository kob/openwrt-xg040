// SPDX-License-Identifier: Apache-2.0

package checksum

import "testing"

func TestCRC32AStandardCheckValue(t *testing.T) {
	if got := CRC32A([]byte("123456789")); got != 0xfc891918 {
		t.Fatalf("CRC32A() = %#08x, want 0xfc891918", got)
	}
}

func TestCRC32AIncremental(t *testing.T) {
	crc := UpdateCRC32A(CRC32AInitial, []byte("1234"))
	crc = UpdateCRC32A(crc, []byte("56789"))
	if got := SumCRC32A(crc); got != 0xfc891918 {
		t.Fatalf("incremental CRC32A = %#08x, want 0xfc891918", got)
	}
}

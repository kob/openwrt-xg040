// SPDX-License-Identifier: Apache-2.0
//go:build linux

package transport

import (
	"os"
	"strconv"
	"testing"
)

func TestKernelDeviceABI(t *testing.T) {
	values := map[string]uint64{
		"AIROHA_XGS_OMCC_C_ABI_VERSION":           deviceABIVersion,
		"AIROHA_XGS_OMCC_C_MAX_CONTENTS":          MaxFrameSize,
		"AIROHA_XGS_OMCC_C_CAP_DS_MIC_VERIFIED":   deviceInfoVerifiedDownstream,
		"AIROHA_XGS_OMCC_C_CAP_US_MIC_SIGNED":     deviceInfoSignedUpstream,
		"AIROHA_XGS_OMCC_C_GET_INFO":              deviceGetInfoIOCTL,
		"AIROHA_XGS_OMCC_C_MAGIC":                 deviceMagic,
		"AIROHA_XGS_OMCC_C_DIRECTION_RX":          deviceDirectionRX,
		"AIROHA_XGS_OMCC_C_DIRECTION_TX":          deviceDirectionTX,
		"AIROHA_XGS_OMCC_C_FLAG_MIC_VERIFIED":     deviceFlagMICVerified,
		"AIROHA_XGS_OMCC_C_FLAG_TRAILER_STRIPPED": deviceFlagTrailerStripped,
		"AIROHA_XGS_OMCC_C_HEADER_SIZE":           deviceHeaderSize,
		"AIROHA_XGS_OMCC_C_STRUCT_SIZE":           deviceHeaderSize,
	}
	if _, present := os.LookupEnv("AIROHA_XGS_OMCC_C_ABI_VERSION"); !present {
		t.Skip("kernel C ABI values were not supplied")
	}
	for name, want := range values {
		raw, present := os.LookupEnv(name)
		if !present {
			t.Fatalf("missing %s", name)
		}
		got, err := strconv.ParseUint(raw, 0, 64)
		if err != nil {
			t.Fatalf("parse %s=%q: %v", name, raw, err)
		}
		if got != want {
			t.Errorf("%s=%#x, Go ABI=%#x", name, got, want)
		}
	}
}

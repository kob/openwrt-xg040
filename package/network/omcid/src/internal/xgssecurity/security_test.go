package xgssecurity

import (
	"encoding/hex"
	"testing"
)

func TestG98071KeyDerivationVector(t *testing.T) {
	msk := mustHex(t, "112233445566778899aabbccddeeff00")
	serial := mustHex(t, "564e445200112233")
	ponTag := mustHex(t, "4f4c542344556677")
	keys, err := DeriveSharedKeys(msk, serial, ponTag)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, keys.MSK[:], "112233445566778899aabbccddeeff00")
	assertHex(t, keys.Session[:], "795fcf6cb215224087430600dd170f07")
	assertHex(t, keys.OMCI[:], "184b8ad4d1ac4af4dd4b339ecc0d3370")
	assertHex(t, keys.PLOAM[:], "e256ce76785c78717c7b3044ab28e2cd")
	assertHex(t, keys.KEK[:], "6f9c99b8361768937e453b165f609710")
}

func TestRegistrationDerivationAndInputLengths(t *testing.T) {
	registrationID := make([]byte, RegistrationSize)
	serial := mustHex(t, "564e445200112233")
	ponTag := mustHex(t, "4f4c542344556677")
	keys, err := DeriveRegistrationKeys(registrationID, serial, ponTag)
	if err != nil {
		t.Fatal(err)
	}
	defaultKey := DefaultPLOAMKey()
	expectedMSK, err := sum128(defaultKey[:], registrationID)
	if err != nil {
		t.Fatal(err)
	}
	if keys.MSK != expectedMSK {
		t.Fatalf("unexpected registration MSK: %x", keys.MSK)
	}
	for _, test := range []struct {
		registrationID []byte
		serial         []byte
		ponTag         []byte
	}{
		{registrationID[:RegistrationSize-1], serial, ponTag},
		{registrationID, serial[:SerialSize-1], ponTag},
		{registrationID, serial, ponTag[:PONTagSize-1]},
	} {
		if _, err := DeriveRegistrationKeys(test.registrationID, test.serial, test.ponTag); err == nil {
			t.Fatal("accepted invalid key-derivation input length")
		}
	}
	if _, err := DeriveSharedKeys(make([]byte, KeySize-1), serial, ponTag); err == nil {
		t.Fatal("accepted invalid master session key length")
	}
}

func TestG98071DownstreamPLOAMVector(t *testing.T) {
	key := mustHex(t, "e256ce76785c78717c7b3044ab28e2cd")
	content := make([]byte, PLOAMContentSize)
	copy(content, mustHex(t, "00130a030445010000"))
	tag, err := PLOAMMIC(key, Downstream, content)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, tag[:], "46398756280814e6")

	frame := append(append([]byte{}, content...), tag[:]...)
	if err := VerifyPLOAM(key, Downstream, frame); err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] ^= 1
	if err := VerifyPLOAM(key, Downstream, frame); err == nil {
		t.Fatal("accepted a PLOAM frame with a modified MIC")
	}
}

func TestG98071UpstreamPLOAMVector(t *testing.T) {
	key := mustHex(t, "e256ce76785c78717c7b3044ab28e2cd")
	content := make([]byte, PLOAMContentSize)
	copy(content, mustHex(t, "0013100003"))
	tag, err := PLOAMMIC(key, Upstream, content)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, tag[:], "feaf8d09208f0d9b")
}

func TestG98071DownstreamOMCIVector(t *testing.T) {
	key := mustHex(t, "184b8ad4d1ac4af4dd4b339ecc0d3370")
	content := mustHex(t,
		"8000490a01000000008000000000000000000000000000000000000000000000"+
			"000000000000000000000028")
	if len(content) != 44 {
		t.Fatalf("bad test vector length: %d", len(content))
	}
	tag, err := OMCIMIC(key, Downstream, content)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, tag[:], "78dca53d")

	frame := append(append([]byte{}, content...), tag[:]...)
	if err := VerifyOMCI(key, Downstream, frame); err != nil {
		t.Fatal(err)
	}
	frame[8] ^= 1
	if err := VerifyOMCI(key, Downstream, frame); err == nil {
		t.Fatal("accepted an OMCI frame with modified content")
	}
}

func TestSecurityPrimitivesRejectInvalidInputs(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := PLOAMMIC(key, Direction(0), make([]byte, PLOAMContentSize)); err == nil {
		t.Fatal("accepted invalid PLOAM direction")
	}
	if _, err := PLOAMMIC(key, Downstream, make([]byte, PLOAMContentSize-1)); err == nil {
		t.Fatal("accepted invalid PLOAM content length")
	}
	if err := VerifyPLOAM(key, Downstream, make([]byte, PLOAMSize-1)); err == nil {
		t.Fatal("accepted invalid PLOAM frame length")
	}
	if _, err := OMCIMIC(key, Upstream, nil); err == nil {
		t.Fatal("accepted empty OMCI content")
	}
	if err := VerifyOMCI(key, Upstream, make([]byte, OMCIMICSize)); err == nil {
		t.Fatal("accepted an empty OMCI frame")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x, want %s", got, want)
	}
}

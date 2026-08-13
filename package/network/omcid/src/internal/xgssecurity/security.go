// Package xgssecurity implements the protocol security primitives defined by
// ITU-T G.9807.1. It does not own keys or establish a trusted OMCC transport.
package xgssecurity

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/aead/cmac"
)

const (
	KeySize          = 16
	RegistrationSize = 36
	SerialSize       = 8
	PONTagSize       = 8
	PLOAMSize        = 48
	PLOAMContentSize = 40
	PLOAMMICSize     = 8
	OMCIMICSize      = 4
)

type Direction byte

const (
	Downstream Direction = 0x01
	Upstream   Direction = 0x02
)

var (
	defaultKey = [KeySize]byte{
		0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
		0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	}
	omciIntegrityLabel  = []byte("OMCIIntegrityKey")
	ploamIntegrityLabel = []byte("PLOAMIntegrtyKey") // G.9807.1 spelling is deliberate.
	keyEncryptionLabel  = []byte("KeyEncryptionKey")
	sessionKeyLabel     = []byte("SessionK")
)

type Keys struct {
	MSK     [KeySize]byte
	Session [KeySize]byte
	OMCI    [KeySize]byte
	PLOAM   [KeySize]byte
	KEK     [KeySize]byte
}

func DefaultPLOAMKey() [KeySize]byte {
	return defaultKey
}

func DeriveRegistrationKeys(registrationID, serial, ponTag []byte) (Keys, error) {
	if len(registrationID) != RegistrationSize {
		return Keys{}, fmt.Errorf("registration ID must be %d bytes", RegistrationSize)
	}
	msk, err := sum128(defaultKey[:], registrationID)
	if err != nil {
		return Keys{}, err
	}
	return DeriveSharedKeys(msk[:], serial, ponTag)
}

func DeriveSharedKeys(msk, serial, ponTag []byte) (Keys, error) {
	if len(msk) != KeySize {
		return Keys{}, fmt.Errorf("master session key must be %d bytes", KeySize)
	}
	if len(serial) != SerialSize {
		return Keys{}, fmt.Errorf("serial number must be %d bytes", SerialSize)
	}
	if len(ponTag) != PONTagSize {
		return Keys{}, fmt.Errorf("PON tag must be %d bytes", PONTagSize)
	}

	var keys Keys
	copy(keys.MSK[:], msk)
	var err error
	sessionContext := make([]byte, 0, SerialSize+PONTagSize+len(sessionKeyLabel))
	sessionContext = append(sessionContext, serial...)
	sessionContext = append(sessionContext, ponTag...)
	sessionContext = append(sessionContext, sessionKeyLabel...)
	keys.Session, err = sum128(keys.MSK[:], sessionContext)
	if err != nil {
		return Keys{}, err
	}
	keys.OMCI, err = sum128(keys.Session[:], omciIntegrityLabel)
	if err != nil {
		return Keys{}, err
	}
	keys.PLOAM, err = sum128(keys.Session[:], ploamIntegrityLabel)
	if err != nil {
		return Keys{}, err
	}
	keys.KEK, err = sum128(keys.Session[:], keyEncryptionLabel)
	if err != nil {
		return Keys{}, err
	}
	return keys, nil
}

func PLOAMMIC(key []byte, direction Direction, content []byte) ([PLOAMMICSize]byte, error) {
	if err := validateDirection(direction); err != nil {
		return [PLOAMMICSize]byte{}, err
	}
	if len(content) != PLOAMContentSize {
		return [PLOAMMICSize]byte{}, fmt.Errorf("PLOAM content must be %d bytes", PLOAMContentSize)
	}

	message := make([]byte, 1+PLOAMContentSize)
	message[0] = byte(direction)
	copy(message[1:], content)
	tag, err := sum(key, message, PLOAMMICSize)
	if err != nil {
		return [PLOAMMICSize]byte{}, err
	}
	var result [PLOAMMICSize]byte
	copy(result[:], tag)
	return result, nil
}

func VerifyPLOAM(key []byte, direction Direction, frame []byte) error {
	if len(frame) != PLOAMSize {
		return fmt.Errorf("PLOAM frame must be %d bytes", PLOAMSize)
	}
	expected, err := PLOAMMIC(key, direction, frame[:PLOAMContentSize])
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected[:], frame[PLOAMContentSize:]) != 1 {
		return errors.New("PLOAM MIC mismatch")
	}
	return nil
}

func OMCIMIC(key []byte, direction Direction, content []byte) ([OMCIMICSize]byte, error) {
	if err := validateDirection(direction); err != nil {
		return [OMCIMICSize]byte{}, err
	}
	if len(content) == 0 {
		return [OMCIMICSize]byte{}, errors.New("OMCI content is empty")
	}

	message := make([]byte, 1+len(content))
	message[0] = byte(direction)
	copy(message[1:], content)
	tag, err := sum(key, message, OMCIMICSize)
	if err != nil {
		return [OMCIMICSize]byte{}, err
	}
	var result [OMCIMICSize]byte
	copy(result[:], tag)
	return result, nil
}

func VerifyOMCI(key []byte, direction Direction, frame []byte) error {
	if len(frame) <= OMCIMICSize {
		return errors.New("OMCI frame is too short")
	}
	content := frame[:len(frame)-OMCIMICSize]
	expected, err := OMCIMIC(key, direction, content)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected[:], frame[len(content):]) != 1 {
		return errors.New("OMCI MIC mismatch")
	}
	return nil
}

func validateDirection(direction Direction) error {
	if direction != Downstream && direction != Upstream {
		return fmt.Errorf("invalid direction code %#x", byte(direction))
	}
	return nil
}

func sum128(key, message []byte) ([KeySize]byte, error) {
	tag, err := sum(key, message, KeySize)
	if err != nil {
		return [KeySize]byte{}, err
	}
	var result [KeySize]byte
	copy(result[:], tag)
	return result, nil
}

func sum(key, message []byte, size int) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("AES-128 key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	tag, err := cmac.Sum(message, block, size)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(tag), nil
}

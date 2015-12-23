// Copyright (c) 2013-2014 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58

import (
	"crypto/sha256"
	"errors"
)

// ErrChecksum indicates that the checksum of a check-encoded string does not verify against
// the checksum.
var ErrChecksum = errors.New("checksum error")

// ErrInvalidFormat indicates that the check-encoded string has an invalid format.
var ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing")

// checksum: first four bytes of sha256^2
func checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

// CheckEncode prepends a version byte and appends a four byte checksum.
// func CheckEncode(input []byte, version byte) string {
// func CheckEncode(input []byte) string {
func CheckEncode(input []byte, version byte) string {
	var b1, b2 byte

	b1 = 0x5F
	b2 = 0xB1
	return CheckEncodeWithVersionBytes(input, b1, b2)
}

func CheckEncodeWithVersionBytes(input []byte, b1, b2 byte) string {
	b := make([]byte, 0, 2+len(input)+4)
	b = append(b, b1)
	b = append(b, b2)
	b = append(b, input[:]...)
	cksum := checksum(b)

	b = append(b, cksum[:]...)
	return Encode(b)
}

// CheckDecode decodes a string that was encoded with CheckEncode and verifies the checksum.
func CheckDecodeWithOneVersionByte(input string) (result []byte, version byte, err error) {
	decoded := Decode(input)
	if len(decoded) < 5 {
		return nil, 0, ErrInvalidFormat
	}
	version = decoded[0]
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, 0, ErrChecksum
	}
	payload := decoded[1 : len(decoded)-4]
	result = append(result, payload...)
	return
}

// CheckDecode decodes a string that was encoded with CheckEncode and verifies the checksum.
func CheckDecodeWithTwoVersionBytes(input string) (result []byte, v1 byte, v2 byte, err error) {
	decoded := Decode(input)
	if len(decoded) < 6 {
		return nil, 0, 0, ErrInvalidFormat
	}

	v1 = decoded[0]
	v2 = decoded[1]

	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, 0, 0, ErrChecksum
	}
	payload := decoded[2 : len(decoded)-4]
	result = append(result, payload...)
	return
}

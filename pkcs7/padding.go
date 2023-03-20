//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package pkcs7

import (
	"errors"
)

var (
	// ErrInvalidPadding is returned when padded data contains an
	// invalid PKCS #7 padding.
	ErrInvalidPadding = errors.New("invalid PKCS #7 padding")
)

// PadLen computes the PKCS #7 padding length length. The function
// returns the padding length and the length of the padded data.
func PadLen(length, blockSize int) (padLen, paddedLen int) {
	padLen = blockSize - length%blockSize
	if padLen == 0 {
		padLen = blockSize
	}
	paddedLen = length + padLen
	return
}

// Pad appends the PKCS #7 padding to the argument slice.
func Pad(buf []byte, blockSize int) []byte {
	padLen, _ := PadLen(len(buf), blockSize)

	for i := 0; i < padLen; i++ {
		buf = append(buf, byte(padLen))
	}

	return buf
}

// UnPad removes the PKCS #7 padding from the buffer and returns a
// slice sharing the argument buffer.
func UnPad(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, ErrInvalidPadding
	}
	padLen := int(buf[len(buf)-1])
	if padLen > len(buf) {
		return nil, ErrInvalidPadding
	}
	return buf[:len(buf)-padLen], nil
}

// UnPadCheck removes the PKCS #7 padding from the buffer and returns
// a slice sharing the argument buffer. This works like UnPad but the
// function also check that the padding bytes are according to the
// PKCS #7 specification.
func UnPadCheck(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, ErrInvalidPadding
	}
	padLen := int(buf[len(buf)-1])
	if padLen > len(buf) {
		return nil, ErrInvalidPadding
	}
	limit := len(buf) - padLen

	var check int
	for i := 0; i < padLen; i++ {
		check |= int(buf[limit+i]) ^ padLen
	}
	if check != 0 {
		return nil, ErrInvalidPadding
	}

	return buf[:limit], nil
}

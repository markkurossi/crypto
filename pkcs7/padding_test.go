//
// encryption_block_test.go
//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package pkcs7

import (
	"testing"
)

var lengths = []struct {
	length    int
	blockSize int
	padLen    int
	paddedLen int
}{
	{
		length:    0,
		blockSize: 16,
		padLen:    16,
		paddedLen: 16,
	},
	{
		length:    1,
		blockSize: 16,
		padLen:    15,
		paddedLen: 16,
	},
	{
		length:    15,
		blockSize: 16,
		padLen:    1,
		paddedLen: 16,
	},
	{
		length:    16,
		blockSize: 16,
		padLen:    16,
		paddedLen: 32,
	},
}

func TestPadLen(t *testing.T) {
	for idx, l := range lengths {
		padLen, paddedLen := PadLen(l.length, l.blockSize)
		if padLen != l.padLen {
			t.Errorf("test %d: padLen %d, expeted %d", idx, padLen, l.padLen)
		}
		if paddedLen != l.paddedLen {
			t.Errorf("test %d: paddedLen %d, expected %d",
				idx, paddedLen, l.paddedLen)
		}
	}
}

func testPad(t *testing.T, check bool) {
	for _, l := range lengths {
		data := make([]byte, l.length)
		for i := 0; i < l.length; i++ {
			data[i] = byte(l.length)
		}

		padded := Pad(data, l.blockSize)

		var err error
		if check {
			data, err = UnPadCheck(padded)
		} else {
			data, err = UnPad(padded)
		}
		if err != nil {
			t.Fatalf("UnPad failed: %v", err)
		}
		if len(data) != l.length {
			t.Fatalf("UnPad: invalid orig length")
		}
		for i := 0; i < l.length; i++ {
			if data[i] != byte(l.length) {
				t.Errorf("UnPad: invalid orig data")
			}
		}
	}
}

func TestPad(t *testing.T) {
	testPad(t, false)
}

func TestPadCheck(t *testing.T) {
	testPad(t, true)
}

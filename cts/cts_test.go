//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package cts

import (
	"bytes"
	"crypto/aes"
	"testing"
)

var tests = []struct {
	key    []byte
	iv     [16]byte
	input  []byte
	output []byte
	nextIV []byte
}{
	{
		key: []byte{
			0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
			0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
		},
		input: []byte{
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20,
		},
		output: []byte{
			0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4,
			0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7, 0xff, 0x7f,
			0x97,
		},
		nextIV: []byte{
			0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4,
			0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7, 0xff, 0x7f,
		},
	},
	{
		key: []byte{
			0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
			0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
		},
		input: []byte{
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20,
		},
		output: []byte{
			0xfc, 0x00, 0x78, 0x3e, 0x0e, 0xfd, 0xb2, 0xc1,
			0xd4, 0x45, 0xd4, 0xc8, 0xef, 0xf7, 0xed, 0x22,
			0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
			0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5,
		},
		nextIV: []byte{
			0xfc, 0x00, 0x78, 0x3e, 0x0e, 0xfd, 0xb2, 0xc1,
			0xd4, 0x45, 0xd4, 0xc8, 0xef, 0xf7, 0xed, 0x22,
		},
	},
	{
		key: []byte{
			0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
			0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
		},
		input: []byte{
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
		},
		output: []byte{
			0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
			0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
			0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
			0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
		},
		nextIV: []byte{
			0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
			0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
		},
	},
	{
		key: []byte{
			0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
			0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
		},
		input: []byte{
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
			0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
			0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c,
		},
		output: []byte{
			0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
			0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
			0xb3, 0xff, 0xfd, 0x94, 0x0c, 0x16, 0xa1, 0x8c,
			0x1b, 0x55, 0x49, 0xd2, 0xf8, 0x38, 0x02, 0x9e,
			0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
			0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5,
		},
		nextIV: []byte{
			0xb3, 0xff, 0xfd, 0x94, 0x0c, 0x16, 0xa1, 0x8c,
			0x1b, 0x55, 0x49, 0xd2, 0xf8, 0x38, 0x02, 0x9e,
		},
	},
	{
		key: []byte{
			0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
			0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
		},
		input: []byte{
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
			0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
			0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
		},
		output: []byte{
			0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
			0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
			0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
			0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
			0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
			0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
		},
		nextIV: []byte{
			0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
			0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
		},
	},
	{
		key: []byte{
			0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
			0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
		},
		input: []byte{
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
			0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
			0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
			0x61, 0x6e, 0x64, 0x20, 0x77, 0x6f, 0x6e, 0x74,
			0x6f, 0x6e, 0x20, 0x73, 0x6f, 0x75, 0x70, 0x2e,
		},
		output: []byte{
			0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
			0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
			0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
			0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
			0x48, 0x07, 0xef, 0xe8, 0x36, 0xee, 0x89, 0xa5,
			0x26, 0x73, 0x0d, 0xbc, 0x2f, 0x7b, 0xc8, 0x40,
			0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
			0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
		},
		nextIV: []byte{
			0x48, 0x07, 0xef, 0xe8, 0x36, 0xee, 0x89, 0xa5,
			0x26, 0x73, 0x0d, 0xbc, 0x2f, 0x7b, 0xc8, 0x40,
		},
	},
}

func TestAESCTS(t *testing.T) {
	for idx, test := range tests {
		b, err := aes.NewCipher(test.key[:])
		if err != nil {
			t.Fatalf("TestAESCTS-%d: aes.NewCipher: %v", idx, err)
		}
		blockMode := NewCTSEncrypter(b, test.iv[:])
		cts := blockMode.(*cts)

		output := make([]byte, len(test.input))
		cts.CryptBlocks(output, test.input)

		if bytes.Compare(output, test.output) != 0 {
			t.Errorf("TestAESCTS-%d: output: %x, expected: %x",
				idx, output, test.output)
		}
		if bytes.Compare(cts.iv, test.nextIV) != 0 {
			t.Errorf("TestAESCTS-%d: nextIV: %x, expected: %x",
				idx, cts.iv, test.nextIV)
		}
	}
}

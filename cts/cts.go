//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

// Package cts implements ciphertext stealing encryption mode. The
// implementation uses the CTS-3 (Kerberos) variant for formatting the
// cipher text.
package cts

import (
	"bytes"
	"crypto/cipher"
)

var (
	_ cipher.BlockMode = &cts{}
)

type cts struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	tmp       []byte
}

// NewCTSEncrypter returns a cipher.BlockMode which encrypts in
// ciphertext stealing mode, using the given cipher.Block. The length
// of the iv must be the same as the cipher.Block's block size.
func NewCTSEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cts.NewCTSEncrypter: IV length must be equal block size")
	}
	return &cts{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		tmp:       make([]byte, b.BlockSize()),
	}
}

// BlockSize implements cipher.BlockMode.BlockSize.
func (cts *cts) BlockSize() int {
	return cts.blockSize
}

// CryptBlocks implements cipher.BlockMode.CryptBlocks.
func (cts *cts) CryptBlocks(dst, src []byte) {
	numBlocks := len(src) / cts.blockSize
	tail := len(src) % cts.blockSize

	if tail != 0 {
		numBlocks++
	} else {
		tail = cts.blockSize
	}

	if numBlocks < 2 {
		panic("cts.CryptBlocks: input must be at least 2 blocks")
	}
	if len(dst) < len(src) {
		panic("cts.CryptBlocks: output smaller than input")
	}

	// Standard CBC for the first numBlocks-1 blocks.
	for i := 0; i < numBlocks-1; i++ {
		copy(cts.tmp, src[i*cts.blockSize:])
		for j, b := range cts.iv {
			cts.tmp[j] ^= b
		}
		cts.b.Encrypt(cts.iv, cts.tmp)
		if i < numBlocks-2 {
			// Store standard CBC output block.
			copy(dst[i*cts.blockSize:], cts.iv)
		} else {
			// Store last ciphertext block.
			copy(dst[(numBlocks-1)*cts.blockSize:], cts.iv)
		}
	}

	// Create last input block.
	copy(cts.tmp, src[(numBlocks-1)*cts.blockSize:])
	for i := tail; i < cts.blockSize; i++ {
		cts.tmp[i] = 0
	}
	for j, b := range cts.iv {
		cts.tmp[j] ^= b
	}
	cts.b.Encrypt(cts.iv, cts.tmp)
	copy(dst[(numBlocks-2)*cts.blockSize:], cts.iv)
}

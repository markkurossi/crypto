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
	_ cipher.BlockMode = &ctsEncrypter{}
	_ cipher.BlockMode = &ctsDecrypter{}
)

type cts struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	tmp       []byte
	tmp2      []byte
}

func newCTS(b cipher.Block, iv []byte) *cts {
	return &cts{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		tmp:       make([]byte, b.BlockSize()),
		tmp2:      make([]byte, b.BlockSize()),
	}
}

type ctsEncrypter cts

// NewCTSEncrypter returns a cipher.BlockMode which encrypts in
// ciphertext stealing mode, using the given cipher.Block. The length
// of the iv must be the same as the cipher.Block's block size.
func NewCTSEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cts.NewCTSEncrypter: IV length must be equal block size")
	}
	return (*ctsEncrypter)(newCTS(b, iv))
}

// BlockSize implements cipher.BlockMode.BlockSize.
func (x *ctsEncrypter) BlockSize() int {
	return x.blockSize
}

// CryptBlocks implements cipher.BlockMode.CryptBlocks.
func (x *ctsEncrypter) CryptBlocks(dst, src []byte) {
	numBlocks := len(src) / x.blockSize
	tail := len(src) % x.blockSize

	if tail != 0 {
		numBlocks++
	} else {
		tail = x.blockSize
	}

	if numBlocks < 2 {
		panic("cts.CryptBlocks: input must be at least 2 blocks")
	}
	if len(dst) < len(src) {
		panic("cts.CryptBlocks: output smaller than input")
	}

	// Standard CBC for the first numBlocks-1 blocks.
	for i := 0; i < numBlocks-1; i++ {
		copy(x.tmp, src[i*x.blockSize:])
		for j, b := range x.iv {
			x.tmp[j] ^= b
		}
		x.b.Encrypt(x.iv, x.tmp)
		if i < numBlocks-2 {
			// Store standard CBC output block.
			copy(dst[i*x.blockSize:], x.iv)
		} else {
			// Store last ciphertext block.
			copy(dst[(numBlocks-1)*x.blockSize:], x.iv)
		}
	}

	// Create last input block.
	copy(x.tmp, src[(numBlocks-1)*x.blockSize:])
	for i := tail; i < x.blockSize; i++ {
		x.tmp[i] = 0
	}
	for j, b := range x.iv {
		x.tmp[j] ^= b
	}
	x.b.Encrypt(x.iv, x.tmp)
	copy(dst[(numBlocks-2)*x.blockSize:], x.iv)
}

type ctsDecrypter cts

// NewCTSDecrypter returns a cipher.BlockMode which decrypts in
// ciphertext stealing mode, using the given cipher.Block. The length
// of the iv must be the same as the cipher.Block's block size.
func NewCTSDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cts.NewCTSDecrypter: IV length must be equal block size")
	}
	return (*ctsDecrypter)(newCTS(b, iv))
}

// BlockSize implements cipher.BlockMode.BlockSize.
func (x *ctsDecrypter) BlockSize() int {
	return x.blockSize
}

// CryptBlocks implements cipher.BlockMode.CryptBlocks.
func (x *ctsDecrypter) CryptBlocks(dst, src []byte) {
	numBlocks := len(src) / x.blockSize
	tail := len(src) % x.blockSize

	if tail != 0 {
		numBlocks++
	} else {
		tail = x.blockSize
	}

	if numBlocks < 2 {
		panic("cts.CryptBlocks: input must be at least 2 blocks")
	}
	if len(dst) < len(src) {
		panic("cts.CryptBlocks: output smaller than input")
	}

	// Standard CBC for the first numBlocks-2 blocks.
	for i := 0; i < numBlocks-2; i++ {
		x.b.Decrypt(dst[i*x.blockSize:], src[i*x.blockSize:])
		for j, b := range x.iv {
			dst[i*x.blockSize+j] ^= b
		}
		copy(x.iv, src[i*x.blockSize:])
	}

	// Decrypt second-to-last cipher block.
	x.b.Decrypt(x.tmp, src[(numBlocks-2)*x.blockSize:])

	// Create padded last cipher block.
	copy(x.tmp2, src[(numBlocks-1)*x.blockSize:])
	copy(x.tmp2[tail:], x.tmp[tail:])

	// Decrypt second-to-last block.
	x.b.Decrypt(dst[(numBlocks-2)*x.blockSize:], x.tmp2)
	for j, b := range x.iv {
		dst[(numBlocks-2)*x.blockSize+j] ^= b
	}
	copy(x.iv, x.tmp2)

	// Finalize last block.
	for j, b := range x.iv {
		x.tmp[j] ^= b
	}
	copy(dst[(numBlocks-1)*x.blockSize:], x.tmp[0:tail])
}

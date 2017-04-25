// aez.go - An AEZ implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package AEZ implements the AEZ AEAD primitive.
package aez

import (
	"crypto/subtle"

	"github.com/minio/blake2b-simd"
)

const (
	extractedKeySize = 3 * 16
	blockSize        = 16
)

var (
	extractBlake2Cfg             = &blake2b.Config{Size: extractedKeySize}
	newAes           aesImplCtor = newRoundVartime
)

func extract(k []byte, extractedKey *[extractedKeySize]byte) {
	if len(k) == extractedKeySize {
		copy(extractedKey[:], k)
	} else {
		h, err := blake2b.New(extractBlake2Cfg)
		if err != nil {
			panic("aez: Extract: " + err.Error())
		}
		defer h.Reset()
		h.Write(k)
		tmp := h.Sum(nil)
		defer memwipe(tmp)
		copy(extractedKey[:], tmp)
	}
}

type aesImpl interface {
	Reset()
	Rounds(*[blockSize]byte, int)
}

type aesImplCtor func(*[extractedKeySize]byte) aesImpl

type eState struct {
	I, J, L [16]byte
	aes     aesImpl
}

func (e *eState) init(k []byte) {
	var extractedKey [extractedKeySize]byte
	defer memwipe(extractedKey[:])

	extract(k, &extractedKey)
	copy(e.I[:], extractedKey[0:16])
	copy(e.J[:], extractedKey[16:32])
	copy(e.L[:], extractedKey[32:48])

	e.aes = newAes(&extractedKey)
}

func (e *eState) reset() {
	memwipe(e.I[:])
	memwipe(e.J[:])
	memwipe(e.L[:])
	e.aes.Reset()
}

// E is the tweakable block cipher E() from the specification.  All the
// scary timing side-channel demons live here, in the call to the AES round
// function.
func (e *eState) E(j int, i uint, src *[blockSize]byte, dst []byte) {
	var buf, delta [blockSize]byte
	defer memwipe(delta[:])

	if len(dst) != blockSize {
		panic("aez: E: len(dst)")
	}

	if j == -1 { // AES10()
		multBlock(i, &e.L, &delta)
		xorBytes(delta[:], src[:], buf[:])
		e.aes.Rounds(&buf, 10)
	} else { // AES4
		var I [blockSize]byte
		defer memwipe(I[:])
		copy(I[:], e.I[:])

		uj := uint(j)
		multBlock(uj, &e.J, &delta)
		multBlock(i%8, &e.L, &buf)
		xorBytes(delta[:], buf[:], delta[:])
		for i = (i + 7) / 8; i > 0; i-- {
			multBlock(2, &I, &I)
		}
		xorBytes(delta[:], I[:], delta[:])
		xorBytes(delta[:], src[:], buf[:])
		e.aes.Rounds(&buf, 4)
	}
	copy(dst[:], buf[:])
}

func multBlock(x uint, src, dst *[blockSize]byte) {
	var t, r [blockSize]byte
	defer memwipe(t[:])
	defer memwipe(r[:])

	copy(t[:], src[:])
	for x != 0 {
		if x&1 != 0 { // This is fine, x isn't data/secret dependent.
			xorBytes(r[:], t[:], r[:])
		}
		doubleBlock(&t)
		x >>= 1
	}
	copy(dst[:], r[:])
}

func doubleBlock(p *[blockSize]byte) {
	tmp := p[0]
	for i := 0; i < 15; i++ {
		p[i] = (p[i] << 1) | (p[i+1] >> 7)
	}
	// p[15] = (p[15] << 1) ^ ((tmp >> 7)?135:0);
	cf := subtle.ConstantTimeByteEq(tmp>>7, 1)
	p[15] = (p[15] << 1) ^ byte(subtle.ConstantTimeSelect(cf, 135, 0))
}

func (e *eState) aezPRF(delta *[blockSize]byte, tau int, result []byte) {
	var buf, ctr [blockSize]byte
	off := 0
	for tau >= 16 {
		i := 15
		xorBytes(delta[:], ctr[:], buf[:])
		e.E(-1, 3, &buf, result[off:off+16])
		for { // ctr += 1
			ctr[i]++
			i--
			if ctr[i+1] != 0 {
				break
			}
		}

		tau -= 16
		off += 16
	}
	if tau > 0 {
		xorBytes(delta[:], ctr[:], buf[:])
		e.E(-1, 3, &buf, buf[:])
		copy(result[off:], buf[:])
	}
}

func memwipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func memwipeU32(b []uint32) {
	for i := range b {
		b[i] = 0
	}
}

func xorBytes(a, b, dst []byte) {
	for i, v := range a {
		dst[i] = v ^ b[i]
	}
}

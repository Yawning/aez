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
	"encoding/binary"

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
func (e *eState) E(j int, i uint, src, dst []byte) {
	var buf, delta [blockSize]byte
	defer memwipe(delta[:])

	if len(src) != blockSize {
		panic("aez: E: len(src)")
	}
	if len(dst) != blockSize {
		panic("aez: E: len(dst)")
	}

	if j == -1 { // AES10()
		multBlock(i, &e.L, &delta)
		xorBytes(delta[:], src, buf[:])
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
		xorBytes(delta[:], src, buf[:])
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

func (e *eState) aezHash(nonce []byte, ad [][]byte, tau int, result []byte) {
	var buf, sum [blockSize]byte
	defer memwipe(buf[:])
	defer memwipe(sum[:])

	if len(result) != blockSize {
		panic("aez: Hash: len(result)")
	}

	// Initialize sum with hash of tau
	binary.BigEndian.PutUint32(buf[12:], uint32(tau))
	e.E(3, 1, buf[:], sum[:])

	// Hash nonce, accumulate into sum
	empty := len(nonce) == 0
	n := nonce
	nBytes := uint(len(nonce))
	for i := uint(1); nBytes >= blockSize; i, nBytes = i+1, nBytes-blockSize {
		e.E(4, i, n[:blockSize], buf[:])
		xorBytes(sum[:], buf[:], sum[:])
		n = n[blockSize:]
	}
	if nBytes > 0 || empty {
		memwipe(buf[:])
		copy(buf[:], n)
		buf[nBytes] = 0x80
		e.E(4, 0, buf[:], buf[:])
		xorBytes(sum[:], buf[:], sum[:])
	}

	// Hash each vector element, accumulate into sum
	for k, p := range ad {
		empty = len(p) == 0
		bytes := uint(len(p))
		for i := uint(1); bytes >= blockSize; i, bytes = i+1, bytes-blockSize {
			e.E(5+k, i, p[:blockSize], buf[:])
			xorBytes(sum[:], buf[:], sum[:])
			p = p[blockSize:]
		}
		if bytes > 0 || empty {
			memwipe(buf[:])
			copy(buf[:], p)
			buf[bytes] = 0x80
			e.E(5+k, 0, buf[:], buf[:])
			xorBytes(sum[:], buf[:], sum[:])
		}
	}

	copy(result, sum[:])
}

func (e *eState) aezPRF(delta *[blockSize]byte, tau int, result []byte) {
	var buf, ctr [blockSize]byte
	defer memwipe(buf[:])

	off := 0
	for tau >= blockSize {
		i := 15
		xorBytes(delta[:], ctr[:], buf[:])
		e.E(-1, 3, buf[:], result[off:off+blockSize])
		for { // ctr += 1
			ctr[i]++
			i--
			if ctr[i+1] != 0 {
				break
			}
		}

		tau -= blockSize
		off += blockSize
	}
	if tau > 0 {
		xorBytes(delta[:], ctr[:], buf[:])
		e.E(-1, 3, buf[:], buf[:])
		copy(result[off:], buf[:])
	}
}

func (e *eState) aezCore(delta *[blockSize]byte, in []byte, d int, out []byte) {

}

func (e *eState) aezTiny(delta *[blockSize]byte, in []byte, d int, out []byte) {
	var rounds, i, j uint
	var buf [2 * blockSize]byte
	var L, R [blockSize]byte
	var step int
	mask, pad := byte(0x00), byte(0x80)

	i = 7
	inBytes := len(in)
	if inBytes == 1 {
		rounds = 24
	} else if inBytes == 2 {
		rounds = 16
	} else if inBytes < 16 {
		rounds = 10
	} else {
		i, rounds = 6, 8
	}

	// Split (inbytes*8)/2 bits into L and R. Beware: May end in nibble.
	copy(L[:], in[:(inBytes+1)/2])
	copy(R[:], in[inBytes/2:inBytes/2+(inBytes+1)/2])
	if inBytes&1 != 0 { // Must shift R left by half a byte
		for k := uint(0); k < uint(inBytes/2); k++ {
			R[k] = (R[k] << 4) | (R[k+1] >> 4)
		}
		R[inBytes/2] = R[inBytes/2] << 4
		pad = 0x08
		mask = 0xf0
	}
	if d != 0 {
		if inBytes < 16 {
			memwipe(buf[:blockSize])
			copy(buf[:], in)
			buf[0] |= 0x80
			xorBytes(delta[:blockSize], buf[:], buf[:])
			e.E(0, 3, buf[:blockSize], buf[:blockSize])
			L[0] ^= (buf[0] & 0x80)
		}
		j, step = rounds-1, -1
	} else {
		step = 1
	}
	for k := uint(0); k < rounds/2; k, j = k+1, uint(int(j)+2*step) {
		memwipe(buf[:blockSize])
		copy(buf[:], R[:(inBytes+1)/2])
		buf[inBytes/2] = (buf[inBytes/2] & mask) | pad
		xorBytes(buf[:blockSize], delta[:], buf[:blockSize])
		buf[15] ^= byte(j)
		e.E(0, i, buf[:blockSize], buf[:blockSize])
		xorBytes(L[:], buf[:blockSize], L[:blockSize])

		memwipe(buf[:blockSize])
		copy(buf[:], L[:(inBytes+1)/2])
		buf[inBytes/2] = (buf[inBytes/2] & mask) | pad
		xorBytes(buf[:blockSize], delta[:], buf[:blockSize])
		buf[15] ^= byte(int(j) + step)
		e.E(0, i, buf[:blockSize], buf[:blockSize])
		xorBytes(R[:], buf[:blockSize], R[:blockSize])
	}
	copy(buf[:], R[:inBytes/2])
	copy(buf[inBytes/2:], L[:(inBytes+1)/2])
	if inBytes&1 != 0 {
		for k := inBytes - 1; k > inBytes/2; k-- {
			buf[k] = (buf[k] >> 4) | (buf[k-1] << 4)
		}
		buf[inBytes/2] = (L[0] >> 4) | (R[inBytes/2] & 0xf0)
	}
	copy(out, buf[:inBytes])
	if inBytes < 16 && d == 0 {
		memwipe(buf[inBytes:blockSize])
		buf[0] |= 0x80
		xorBytes(delta[:], buf[:blockSize], buf[:blockSize])
		e.E(0, 3, buf[:blockSize], buf[:blockSize])
		out[0] ^= buf[0] & 0x80
	}
}

func (e *eState) encipher(delta *[blockSize]byte, in, out []byte) {
	if len(in) == 0 {
		return
	}

	if len(in) < 32 {
		e.aezTiny(delta, in, 0, out)
	} else {
		e.aezCore(delta, in, 0, out)
	}
}

func (e *eState) decipher(delta *[blockSize]byte, in, out []byte) {
	if len(in) == 0 {
		return
	}

	if len(in) < 32 {
		e.aezTiny(delta, in, 1, out)
	} else {
		e.aezCore(delta, in, 1, out)
	}
}

func Encrypt(key []byte, nonce []byte, ad [][]byte, tau int, m []byte) []byte {
	var delta [blockSize]byte
	x := make([]byte, tau+len(m))

	var e eState
	defer e.reset()

	e.init(key)
	e.aezHash(nonce, ad, tau*8, delta[:])
	if len(m) == 0 {
		e.aezPRF(&delta, tau, x)
	} else {
		copy(x, m)
		e.encipher(&delta, x, x)
	}

	return x
}

func Decrypt(key []byte, nonce []byte, ad [][]byte, tau int, c []byte) ([]byte, bool) {
	var delta [blockSize]byte
	sum := byte(0)
	x := make([]byte, len(c))

	if len(c) < tau {
		return nil, false
	}

	var e eState
	defer e.reset()

	e.init(key)
	e.aezHash(nonce, ad, tau*8, delta[:])
	if len(c) == tau {
		e.aezPRF(&delta, tau, x)
		for i := 0; i < tau; i++ {
			sum |= x[i] ^ c[i]
		}
		x = nil
	} else {
		e.decipher(&delta, c, x)
		for i := 0; i < tau; i++ {
			sum |= x[len(c)-tau+i]
		}
		if sum == 0 {
			x = x[:len(c)-tau]
		}
	}
	if sum != 0 { // return true if valid, false if invalid
		return nil, false
	}
	return x, true
}

func memwipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func xorBytes(a, b, dst []byte) {
	for i, v := range a {
		dst[i] = v ^ b[i]
	}
}

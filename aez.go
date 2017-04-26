// aez.go - An AEZ implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// This implementation is primarily derived from:
//
// AEZ v5 reference code. AEZ info: http://www.cs.ucdavis.edu/~rogaway/aez
//
// ** This version is slow and susceptible to side-channel attacks. **
// ** Do not use for any purpose other than to understand AEZ.      **
//
// Written by Ted Krovetz (ted@krovetz.net). Last modified 21 March 2017.
//
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
//

// Package aez implements the AEZ AEAD primitive.
//
// See: http://web.cs.ucdavis.edu/~rogaway/aez/
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

	doubledI      [16]byte // Running double.
	doubledI1     [16]byte // Doubled e.I.
	doubledICount uint
}

func (e *eState) init(k []byte) {
	var extractedKey [extractedKeySize]byte
	defer memwipe(extractedKey[:])

	extract(k, &extractedKey)
	copy(e.I[:], extractedKey[0:16])
	copy(e.J[:], extractedKey[16:32])
	copy(e.L[:], extractedKey[32:48])

	copy(e.doubledI[:], e.I[:])
	multBlock(2, &e.I, &e.doubledI1)
	multBlock(2, &e.doubledI1, &e.doubledI)
	e.doubledICount = 2

	e.aes = newAes(&extractedKey)
}

func (e *eState) reset() {
	memwipe(e.I[:])
	memwipe(e.J[:])
	memwipe(e.L[:])
	memwipe(e.doubledI[:])
	memwipe(e.doubledI1[:])
	e.aes.Reset()
}

// E is the tweakable block cipher E() from the specification.  All the
// scary timing side-channel demons live here, in the call to the AES round
// function.
func (e *eState) E(j int, i uint, src, dst []byte) {
	var buf, delta [blockSize]byte
	var I [blockSize]byte

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
		uj := uint(j)
		multBlock(uj, &e.J, &delta)
		multBlock(i%8, &e.L, &buf)
		xorBytes(delta[:], buf[:], delta[:])

		// Cache doubled I values.
		//
		// XXX: This can be improved to remove some copies and the memwipe.
		doubleTarget := (i + 7) / 8
		switch doubleTarget {
		case 0:
			copy(I[:], e.I[:])
		case 1:
			copy(I[:], e.doubledI1[:])
		default:
			if e.doubledICount > doubleTarget {
				// The target went backwards, probably the pass 1 -> pass 2
				// transition.
				copy(I[:], e.doubledI1[:])
				for i = doubleTarget; i > 1; i-- {
					multBlock(2, &I, &I)
				}
				copy(e.doubledI[:], I[:])
				e.doubledICount = doubleTarget
			} else if e.doubledICount == doubleTarget {
				// Cache hit.
				copy(I[:], e.doubledI[:])
			} else {
				// Need to double at least once.
				copy(I[:], e.doubledI[:])
				for i = doubleTarget; i > e.doubledICount; i-- {
					multBlock(2, &I, &I)
				}
				copy(e.doubledI[:], I[:])
				e.doubledICount = doubleTarget
			}
		}

		// The reference code does this, which, while explcitly clear,
		// is horrific for performance, since it starts the doubling process
		// from scratch on each invocation to E.
		//
		//   copy(I[:], e.I[:])
		//   for i = (i + 7) / 8; i > 0; i-- {
		//     multBlock(2, &I, &I)
		//   }

		xorBytes(delta[:], I[:], delta[:])
		xorBytes(delta[:], src, buf[:])
		e.aes.Rounds(&buf, 4)
	}
	copy(dst[:], buf[:])

	memwipe(delta[:])
	memwipe(I[:])
}

func multBlock(x uint, src, dst *[blockSize]byte) {
	var t, r [blockSize]byte

	copy(t[:], src[:])
	for x != 0 {
		if x&1 != 0 { // This is fine, x isn't data/secret dependent.
			xorBytes(r[:], t[:], r[:])
		}
		doubleBlock(&t)
		x >>= 1
	}
	copy(dst[:], r[:])

	memwipe(t[:])
	memwipe(r[:])
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
		xorBytes(delta[:], ctr[:], buf[:])
		e.E(-1, 3, buf[:], result[off:off+blockSize])
		i := 15
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

func (e *eState) aezCore(delta *[blockSize]byte, in []byte, d uint, out []byte) {
	var tmp, X, Y, S [blockSize]byte
	inOrig := in
	outOrig := out
	inBytes, inBytesOrig := len(in), len(in)
	defer memwipe(X[:])
	defer memwipe(Y[:])
	defer memwipe(S[:])

	// Pass 1 over in[0:-32], store intermediate values in out[0:-32]
	for i := uint(1); inBytes >= 64; i, inBytes = i+1, inBytes-32 {
		e.E(1, i, in[blockSize:blockSize*2], tmp[:])
		xorBytes(in, tmp[:], out[:blockSize])
		e.E(0, 0, out[:blockSize], tmp[:])
		xorBytes(in[blockSize:], tmp[:], out[blockSize:blockSize*2])
		xorBytes(out[blockSize:], X[:], X[:])
		in, out = in[32:], out[32:]
	}

	// Finish X calculation
	inBytes -= 32 // inbytes now has fragment length 0..31
	if inBytes >= blockSize {
		e.E(0, 4, in[:blockSize], tmp[:])
		xorBytes(X[:], tmp[:], X[:])
		inBytes -= blockSize
		in, out = in[blockSize:], out[blockSize:]
		memwipe(tmp[:])
		copy(tmp[:], in[:inBytes])
		tmp[inBytes] = 0x80
		e.E(0, 5, tmp[:], tmp[:])
		xorBytes(X[:], tmp[:], X[:])
	} else if inBytes > 0 {
		memwipe(tmp[:])
		copy(tmp[:], in[:inBytes])
		tmp[inBytes] = 0x80
		e.E(0, 4, tmp[:], tmp[:])
		xorBytes(X[:], tmp[:], X[:])
	}
	in = in[inBytes:]
	out = out[inBytes:]

	// Calculate S
	e.E(0, 1+d, in[blockSize:2*blockSize], tmp[:])
	xorBytes(X[:], in, out[:blockSize])
	xorBytes(delta[:], out, out[:blockSize])
	xorBytes(tmp[:], out, out[:blockSize])
	e.E(-1, 1+d, out[:blockSize], tmp[:])
	xorBytes(in[blockSize:], tmp[:], out[blockSize:blockSize*2])
	xorBytes(out, out[blockSize:], S[:])

	// Pass 2 over intermediate values in out[32..]. Final values written
	inBytes = inBytesOrig
	out, in = outOrig, inOrig
	for i := uint(1); inBytes >= 64; i, inBytes = i+1, inBytes-32 {
		e.E(2, i, S[:], tmp[:])
		xorBytes(out, tmp[:], out[:blockSize])
		xorBytes(out[blockSize:], tmp[:], out[blockSize:blockSize*2])
		xorBytes(out, Y[:], Y[:])
		e.E(0, 0, out[blockSize:blockSize*2], tmp[:])
		xorBytes(out, tmp[:], out[:blockSize])
		e.E(1, i, out[:blockSize], tmp[:])
		xorBytes(out[blockSize:], tmp[:], out[blockSize:blockSize*2])
		copy(tmp[:], out[:blockSize])
		copy(out[:blockSize], out[blockSize:])
		copy(out[blockSize:], tmp[:])

		in, out = in[32:], out[32:]
	}

	// Finish Y calculation and finish encryption of fragment bytes
	inBytes -= 32 // inbytes now has fragment length 0..31
	if inBytes >= blockSize {
		e.E(-1, 4, S[:], tmp[:])
		xorBytes(in, tmp[:], out[:blockSize])
		e.E(0, 4, out[:blockSize], tmp[:])
		xorBytes(Y[:], tmp[:], Y[:])
		inBytes -= blockSize
		in, out = in[blockSize:], out[blockSize:]
		e.E(-1, 5, S[:], tmp[:])
		xorBytes(in, tmp[:], tmp[:inBytes]) // non-16 byte xorBytes()
		copy(out, tmp[:inBytes])
		memwipe(tmp[inBytes:])
		tmp[inBytes] = 0x80
		e.E(0, 5, tmp[:], tmp[:])
		xorBytes(Y[:], tmp[:], Y[:])
	} else if inBytes > 0 {
		e.E(-1, 4, S[:], tmp[:])
		xorBytes(in, tmp[:], tmp[:inBytes]) // non-16 byte xorBytes()
		copy(out, tmp[:inBytes])
		memwipe(tmp[inBytes:])
		tmp[inBytes] = 0x80
		e.E(0, 4, tmp[:], tmp[:])
		xorBytes(Y[:], tmp[:], Y[:])
	}
	/* in, */ out = /* in[inBytes:], */ out[inBytes:]

	// Finish encryption of last two blocks
	e.E(-1, 2-d, out[blockSize:], tmp[:])
	xorBytes(out, tmp[:], out[:blockSize])
	e.E(0, 2-d, out[:blockSize], tmp[:])
	xorBytes(tmp[:], out[blockSize:], out[blockSize:2*blockSize])
	xorBytes(delta[:], out[blockSize:], out[blockSize:2*blockSize])
	xorBytes(Y[:], out[blockSize:], out[blockSize:2*blockSize])
	copy(tmp[:], out[:blockSize])
	copy(out[:blockSize], out[blockSize:])
	copy(out[blockSize:], tmp[:])
}

func (e *eState) aezTiny(delta *[blockSize]byte, in []byte, d uint, out []byte) {
	var rounds, i, j uint
	var buf [2 * blockSize]byte
	var L, R [blockSize]byte
	var step int
	mask, pad := byte(0x00), byte(0x80)
	defer memwipe(L[:])
	defer memwipe(R[:])

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
			xorBytes(delta[:], buf[:], buf[:blockSize])
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
		xorBytes(buf[:], delta[:], buf[:blockSize])
		buf[15] ^= byte(j)
		e.E(0, i, buf[:blockSize], buf[:blockSize])
		xorBytes(L[:], buf[:], L[:blockSize])

		memwipe(buf[:blockSize])
		copy(buf[:], L[:(inBytes+1)/2])
		buf[inBytes/2] = (buf[inBytes/2] & mask) | pad
		xorBytes(buf[:], delta[:], buf[:blockSize])
		buf[15] ^= byte(int(j) + step)
		e.E(0, i, buf[:blockSize], buf[:blockSize])
		xorBytes(R[:], buf[:], R[:blockSize])
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
		xorBytes(delta[:], buf[:], buf[:blockSize])
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
	if len(a) < len(dst) || len(b) < len(dst) {
		panic("aez: xorBytes len")
	}
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
}

// aez.go - An AEZ implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
//
// This implementation is primarily derived from the AEZ v5 reference code
// available at: http://www.cs.ucdavis.edu/~rogaway/aez
//
// It started off as a straight forward port of the `ref` variant, but has
// pulled in ideas from `aesni`.

// Package aez implements the AEZ AEAD primitive.
//
// This implementation is NOT CONSTANT TIME ON ALL PLATFORMS.
//
// See: http://web.cs.ucdavis.edu/~rogaway/aez/
package aez

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/minio/blake2b-simd"
)

const (
	// Version is the version of the AEZ specification implemented.
	Version = "v5"

	extractedKeySize = 3 * 16
	blockSize        = 16
)

var (
	extractBlake2Cfg             = &blake2b.Config{Size: extractedKeySize}
	newAes           aesImplCtor = newRoundVartime
	zero                         = [blockSize]byte{}
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
		copy(extractedKey[:], tmp)
		memwipe(tmp)
	}
}

type aesImpl interface {
	Reset()
	Rounds(*[blockSize]byte, int)
}

type aesImplCtor func(*[extractedKeySize]byte) aesImpl

type eState struct {
	I   [2][16]byte // 1I, 2I
	J   [3][16]byte // 1J, 2J, 4J
	L   [8][16]byte // 0L, 1L ... 7L
	aes aesImpl
}

func (e *eState) init(k []byte) {
	var extractedKey [extractedKeySize]byte
	defer memwipe(extractedKey[:])

	extract(k, &extractedKey)

	copy(e.I[0][:], extractedKey[0:16]) // 1I
	multBlock(2, &e.I[0], &e.I[1])      // 2I

	copy(e.J[0][:], extractedKey[16:32]) // 1J
	multBlock(2, &e.J[0], &e.J[1])       // 2J
	multBlock(2, &e.J[1], &e.J[2])       // 4J

	// The upstream `aesni` code only stores L1, L2, and L4, but it has
	// the benefit of being written in a real language that has vector
	// intrinsics.

	// multBlock(0, &e.L, &e.L[0])                // L0 (all `0x00`s)
	copy(e.L[1][:], extractedKey[32:48])          // L1
	multBlock(2, &e.L[1], &e.L[2])                // L2=L1*2
	xorBytes1x16(e.L[2][:], e.L[1][:], e.L[3][:]) // L3 = L2+L1
	multBlock(2, &e.L[2], &e.L[4])                // L4 = L2*2
	xorBytes1x16(e.L[4][:], e.L[1][:], e.L[5][:]) // L5 = L4+L1
	multBlock(2, &e.L[3], &e.L[6])                // L6 = L3*2
	xorBytes1x16(e.L[6][:], e.L[1][:], e.L[7][:]) // L7 = L6+L1

	e.aes = newAes(&extractedKey)
}

func (e *eState) reset() {
	for i := range e.I {
		memwipe(e.I[i][:])
	}
	for i := range e.J {
		memwipe(e.J[i][:])
	}
	for i := range e.L {
		memwipe(e.L[i][:])
	}
	e.aes.Reset()
}

func multBlock(x uint, src, dst *[blockSize]byte) {
	var t, r [blockSize]byte

	copy(t[:], src[:])
	for x != 0 {
		if x&1 != 0 { // This is fine, x isn't data/secret dependent.
			xorBytes1x16(r[:], t[:], r[:])
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
	s := subtle.ConstantTimeByteEq(tmp>>7, 1)
	p[15] = (p[15] << 1) ^ byte(subtle.ConstantTimeSelect(s, 135, 0))
}

func (e *eState) e4(j, i, l *[blockSize]byte, in []byte, dst *[blockSize]byte) {
	xorBytes4x16(j[:], i[:], l[:], in, dst)
	e.aes.Rounds(dst, 4)
}

func (e *eState) e10(l *[blockSize]byte, in []byte, dst *[blockSize]byte) {
	xorBytes1x16(in, l[:], dst[:])
	e.aes.Rounds(dst, 10)
}

func (e *eState) aezHash(nonce []byte, ad [][]byte, tau int, result []byte) {
	var buf, sum, I, J [blockSize]byte

	if len(result) != blockSize {
		panic("aez: Hash: len(result)")
	}

	// Initialize sum with hash of tau
	binary.BigEndian.PutUint32(buf[12:], uint32(tau))
	xorBytes1x16(e.J[0][:], e.J[1][:], J[:]) // J ^ J2
	e.e4(&J, &e.I[1], &e.L[1], buf[:], &sum) // E(3,1)

	// Hash nonce, accumulate into sum
	empty := len(nonce) == 0
	n := nonce
	nBytes := uint(len(nonce))
	copy(I[:], e.I[1][:])
	for i := uint(1); nBytes >= blockSize; i, nBytes = i+1, nBytes-blockSize {
		e.e4(&e.J[2], &I, &e.L[i%8], n[:blockSize], &buf) // E(4,i)
		xorBytes1x16(sum[:], buf[:], sum[:])
		n = n[blockSize:]
		if i%8 == 0 {
			doubleBlock(&I)
		}
	}
	if nBytes > 0 || empty {
		memwipe(buf[:])
		copy(buf[:], n)
		buf[nBytes] = 0x80
		e.e4(&e.J[2], &e.I[0], &e.L[0], buf[:], &buf) // E(4,0)
		xorBytes1x16(sum[:], buf[:], sum[:])
	}

	// Hash each vector element, accumulate into sum
	for k, p := range ad {
		empty = len(p) == 0
		bytes := uint(len(p))
		copy(I[:], e.I[1][:])
		multBlock(uint(5+k), &e.J[0], &J) // XXX/performance.
		for i := uint(1); bytes >= blockSize; i, bytes = i+1, bytes-blockSize {
			e.e4(&J, &I, &e.L[i%8], p[:blockSize], &buf) // E(5+k,i)
			xorBytes1x16(sum[:], buf[:], sum[:])
			p = p[blockSize:]
			if i%8 == 0 {
				doubleBlock(&I)
			}
		}
		if bytes > 0 || empty {
			memwipe(buf[:])
			copy(buf[:], p)
			buf[bytes] = 0x80
			e.e4(&J, &e.I[0], &e.L[0], buf[:], &buf) // E(5+k,0)
			xorBytes1x16(sum[:], buf[:], sum[:])
		}
	}

	memwipe(I[:])
	memwipe(J[:])

	copy(result, sum[:])
}

func (e *eState) aezPRF(delta *[blockSize]byte, tau int, result []byte) {
	var buf, ctr [blockSize]byte

	off := 0
	for tau >= blockSize {
		// xorBytes1x16(delta, ctr, buf)
		// E(-1, 3, buf, result[off:off+blockSize])
		xorBytes3x16(delta, &ctr, &e.L[3], &buf)
		e.aes.Rounds(&buf, 10)
		copy(result[off:], buf[:])

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
		// xorBytes1x16(delta, ctr, buf)
		// E(-1, 3, buf, result[off:off+blockSize])
		xorBytes3x16(delta, &ctr, &e.L[3], &buf)
		e.aes.Rounds(&buf, 10)

		copy(result[off:], buf[:])
	}

	memwipe(buf[:])
}

func (e *eState) aezCorePass1(delta *[blockSize]byte, in, out []byte, d uint, X, S *[blockSize]byte) int {
	var tmp, I [blockSize]byte
	inBytes := len(in)
	inBytesOrig := inBytes

	// Pass 1 over in[0:-32], store intermediate values in out[0:-32]
	// XXX/performance: Process multiple blocks at once.
	copy(I[:], e.I[1][:])
	for i := uint(1); inBytes >= 64; i, inBytes = i+1, inBytes-32 {
		e.e4(&e.J[0], &I, &e.L[i%8], in[blockSize:blockSize*2], &tmp) // E(1,i)
		xorBytes1x16(in[:], tmp[:], out[:blockSize])
		e.e4(&zero, &e.I[0], &e.L[0], out[:blockSize], &tmp) // E(0,0)
		xorBytes1x16(in[blockSize:], tmp[:], out[blockSize:blockSize*2])
		xorBytes1x16(out[blockSize:], X[:], X[:])

		in, out = in[32:], out[32:]
		if i%8 == 0 {
			doubleBlock(&I)
		}
	}

	// Finish X calculation
	inBytes -= 32 // inbytes now has fragment length 0..31
	if inBytes >= blockSize {
		e.e4(&zero, &e.I[1], &e.L[4], in[:blockSize], &tmp) // E(0,4)
		xorBytes1x16(X[:], tmp[:], X[:])
		inBytes -= blockSize
		in = in[blockSize:]
		memwipe(tmp[:])
		copy(tmp[:], in[:inBytes])
		tmp[inBytes] = 0x80
		e.e4(&zero, &e.I[1], &e.L[5], tmp[:], &tmp) // E(0,5)
		xorBytes1x16(X[:], tmp[:], X[:])
	} else if inBytes > 0 {
		memwipe(tmp[:])
		copy(tmp[:], in[:inBytes])
		tmp[inBytes] = 0x80
		e.e4(&zero, &e.I[1], &e.L[4], tmp[:], &tmp) // E(0,4)
		xorBytes1x16(X[:], tmp[:], X[:])
	}
	in = in[inBytes:]

	memwipe(I[:])
	memwipe(tmp[:])

	return inBytesOrig - len(in)
}

func (e *eState) aezCorePass2(in, out []byte, Y, S *[blockSize]byte) int {
	var tmp, I [blockSize]byte
	inBytes := len(in)
	inBytesOrig := inBytes

	// Pass 2 over intermediate values in out[32..]. Final values written
	// XXX/performance: Process multiple blocks at once.
	copy(I[:], e.I[1][:])
	for i := uint(1); inBytes >= 64; i, inBytes = i+1, inBytes-32 {
		e.e4(&e.J[1], &I, &e.L[i%8], S[:], &tmp) // E(2,i)
		xorBytes1x16(out, tmp[:], out[:blockSize])
		xorBytes1x16(out[blockSize:], tmp[:], out[blockSize:blockSize*2])
		xorBytes1x16(out, Y[:], Y[:])
		e.e4(&zero, &e.I[0], &e.L[0], out[blockSize:blockSize*2], &tmp) // E(0,0)
		xorBytes1x16(out, tmp[:], out[:blockSize])
		e.e4(&e.J[0], &I, &e.L[i%8], out[:blockSize], &tmp) // E(1,i)
		xorBytes1x16(out[blockSize:], tmp[:], out[blockSize:blockSize*2])
		copy(tmp[:], out[:blockSize])
		copy(out[:blockSize], out[blockSize:])
		copy(out[blockSize:], tmp[:])

		in, out = in[32:], out[32:]
		if i%8 == 0 {
			doubleBlock(&I)
		}
	}

	// Finish Y calculation and finish encryption of fragment bytes
	inBytes -= 32 // inbytes now has fragment length 0..31
	if inBytes >= blockSize {
		e.e10(&e.L[4], S[:], &tmp) // E(-1,4)
		xorBytes1x16(in, tmp[:], out[:blockSize])
		e.e4(&zero, &e.I[1], &e.L[4], out[:blockSize], &tmp) // E(0,4)
		xorBytes1x16(Y[:], tmp[:], Y[:])
		inBytes -= blockSize
		in, out = in[blockSize:], out[blockSize:]
		e.e10(&e.L[5], S[:], &tmp)          // E(-1,5)
		xorBytes(in, tmp[:], tmp[:inBytes]) // non-16 byte xorBytes()
		copy(out, tmp[:inBytes])
		memwipe(tmp[inBytes:])
		tmp[inBytes] = 0x80
		e.e4(&zero, &e.I[1], &e.L[5], tmp[:], &tmp) // E(0,5)
		xorBytes1x16(Y[:], tmp[:], Y[:])
	} else if inBytes > 0 {
		e.e10(&e.L[4], S[:], &tmp)          // E(-1, 4)
		xorBytes(in, tmp[:], tmp[:inBytes]) // non-16 byte xorBytes()
		copy(out, tmp[:inBytes])
		memwipe(tmp[inBytes:])
		tmp[inBytes] = 0x80
		e.e4(&zero, &e.I[1], &e.L[4], tmp[:], &tmp) // E(0,4)
		xorBytes1x16(Y[:], tmp[:], Y[:])
	}
	in = in[inBytes:]

	memwipe(I[:])
	memwipe(tmp[:])

	return inBytesOrig - len(in)
}

func (e *eState) aezCore(delta *[blockSize]byte, in []byte, d uint, out []byte) {
	var tmp, X, Y, S [blockSize]byte
	inOrig, outOrig := in, out

	// Compute X and store intermediate results
	off := e.aezCorePass1(delta, in, out, d, &X, &S)
	in = in[off:]
	out = out[off:]

	// Calculate S
	e.e4(&zero, &e.I[1], &e.L[(1+d)%8], in[blockSize:2*blockSize], &tmp) // E(0,1+d)
	xorBytes1x16(X[:], in, out[:blockSize])
	xorBytes1x16(delta[:], out, out[:blockSize])
	xorBytes1x16(tmp[:], out, out[:blockSize])
	e.e10(&e.L[(1+d)%8], out[:blockSize], &tmp) // E(-1,1+d)
	xorBytes1x16(in[blockSize:], tmp[:], out[blockSize:blockSize*2])
	xorBytes1x16(out, out[blockSize:], S[:])
	// XXX/performance: Early abort if tag is corrupted.

	// Pass 2 over intermediate values in out[32..]. Final values written
	out, in = outOrig, inOrig
	off = e.aezCorePass2(in, out, &Y, &S)
	out = outOrig[off:]

	// Finish encryption of last two blocks
	e.e10(&e.L[(2-d)%8], out[blockSize:], &tmp) // E(-1,2-d)
	xorBytes1x16(out, tmp[:], out[:blockSize])
	e.e4(&zero, &e.I[1], &e.L[(2-d)%8], out[:blockSize], &tmp) // E(0,2-d)
	xorBytes1x16(tmp[:], out[blockSize:], out[blockSize:2*blockSize])
	xorBytes1x16(delta[:], out[blockSize:], out[blockSize:2*blockSize])
	xorBytes1x16(Y[:], out[blockSize:], out[blockSize:2*blockSize])
	copy(tmp[:], out[:blockSize])
	copy(out[:blockSize], out[blockSize:])
	copy(out[blockSize:], tmp[:])

	memwipe(X[:])
	memwipe(Y[:])
	memwipe(S[:])
}

func (e *eState) aezTiny(delta *[blockSize]byte, in []byte, d uint, out []byte) {
	var rounds, i, j uint
	var buf [2 * blockSize]byte
	var L, R [blockSize]byte
	var step int
	mask, pad := byte(0x00), byte(0x80)
	defer memwipe(L[:])
	defer memwipe(R[:])

	var tmp [16]byte

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
			xorBytes1x16(delta[:], buf[:], buf[:blockSize])
			e.e4(&zero, &e.I[1], &e.L[3], buf[:blockSize], &tmp) // E(0,3)
			L[0] ^= (tmp[0] & 0x80)
		}
		j, step = rounds-1, -1
	} else {
		step = 1
	}
	for k := uint(0); k < rounds/2; k, j = k+1, uint(int(j)+2*step) {
		memwipe(buf[:blockSize])
		copy(buf[:], R[:(inBytes+1)/2])
		buf[inBytes/2] = (buf[inBytes/2] & mask) | pad
		xorBytes1x16(buf[:], delta[:], buf[:blockSize])
		buf[15] ^= byte(j)
		e.e4(&zero, &e.I[1], &e.L[i], buf[:blockSize], &tmp) // E(0,i)
		xorBytes1x16(L[:], tmp[:], L[:blockSize])

		memwipe(buf[:blockSize])
		copy(buf[:], L[:(inBytes+1)/2])
		buf[inBytes/2] = (buf[inBytes/2] & mask) | pad
		xorBytes1x16(buf[:], delta[:], buf[:blockSize])
		buf[15] ^= byte(int(j) + step)
		e.e4(&zero, &e.I[1], &e.L[i], buf[:blockSize], &tmp) // E(0,i)
		xorBytes1x16(R[:], tmp[:], R[:blockSize])
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
		xorBytes1x16(delta[:], buf[:], buf[:blockSize])
		e.e4(&zero, &e.I[1], &e.L[3], buf[:blockSize], &tmp) // E(0,3)
		out[0] ^= tmp[0] & 0x80
	}

	memwipe(tmp[:])
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

// Encrypt encrypts and authenticates the plaintext, authenticates the
// additional data, and returns the resulting ciphertext.  The length
// of the authentication tag in bytes is specified by tau.
func Encrypt(key []byte, nonce []byte, additionalData [][]byte, tau int, plaintext []byte) []byte {
	var delta [blockSize]byte
	x := make([]byte, tau+len(plaintext))

	var e eState
	defer e.reset()

	e.init(key)
	e.aezHash(nonce, additionalData, tau*8, delta[:])
	if len(plaintext) == 0 {
		e.aezPRF(&delta, tau, x)
	} else {
		copy(x, plaintext)
		e.encipher(&delta, x, x)
	}

	return x
}

// Decrypt decrypts and authenticates the ciphertext, authenticates the
// additional data, and if successful returns the plaintext and true.  The
// length of the expected authentication tag in bytes is specified by tau.
func Decrypt(key []byte, nonce []byte, additionalData [][]byte, tau int, ciphertext []byte) ([]byte, bool) {
	var delta [blockSize]byte
	sum := byte(0)
	x := make([]byte, len(ciphertext))

	if len(ciphertext) < tau {
		return nil, false
	}

	var e eState
	defer e.reset()

	e.init(key)
	e.aezHash(nonce, additionalData, tau*8, delta[:])
	if len(ciphertext) == tau {
		e.aezPRF(&delta, tau, x)
		for i := 0; i < tau; i++ {
			sum |= x[i] ^ ciphertext[i]
		}
		x = nil
	} else {
		e.decipher(&delta, ciphertext, x)
		for i := 0; i < tau; i++ {
			sum |= x[len(ciphertext)-tau+i]
		}
		if sum == 0 {
			x = x[:len(ciphertext)-tau]
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

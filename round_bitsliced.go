// round_bitsliced.go - Constant time AES round function.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package aez

import "git.schwanenlied.me/yawning/bsaes.git/ct32"

type roundBitsliced struct {
	ct32.Impl32
	skey [32]uint32 // I, J, L, 0
}

func newRoundBitsliced(extractedKey *[extractedKeySize]byte) aesImpl {
	r := new(roundBitsliced)
	for i := 0; i < 3; i++ {
		r.RkeyOrtho(r.skey[i*8:], extractedKey[i*16:])
	}

	return r
}

func (r *roundBitsliced) Reset() {
	memwipeU32(r.skey[:])
}

func (r *roundBitsliced) AES4(j, i, l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint32
	xorBytes4x16(j[:], i[:], l[:], src, dst[:])

	r.Load4xU32(&q, dst[:])
	r.Ortho(q[:])
	r.roundx2(&q, r.skey[8:])  // J
	r.roundx2(&q, r.skey[0:])  // I
	r.roundx2(&q, r.skey[16:]) // L
	r.roundx2(&q, r.skey[24:]) // zero
	r.Ortho(q[:])
	r.Store4xU32(dst[:], &q)
}

func (r *roundBitsliced) AES10(l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint32
	xorBytes1x16(src, l[:], dst[:])

	r.Load4xU32(&q, dst[:])
	r.Ortho(q[:])
	for i := 0; i < 3; i++ {
		r.roundx2(&q, r.skey[0:])  // I
		r.roundx2(&q, r.skey[8:])  // J
		r.roundx2(&q, r.skey[16:]) // L
	}
	r.roundx2(&q, r.skey[0:]) // I
	r.Ortho(q[:])
	r.Store4xU32(dst[:], &q)
}

func (r *roundBitsliced) roundx2(q *[8]uint32, k []uint32) {
	r.Sbox(q)
	r.ShiftRows(q)
	r.MixColumns(q)
	r.AddRoundKey(q, k)
}

func memwipeU32(b []uint32) {
	for i := range b {
		b[i] = 0
	}
}

// TODO:
// * The bitsliced round function processes blocks in parallel, utilize this
//   for much better performance.
// * Use bsaes.Impl64 when it exists.

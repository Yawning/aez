// round_bitsliced64.go - 64bit constant time AES round function.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package aez

import "git.schwanenlied.me/yawning/bsaes.git/ct64"

type roundB64 struct {
	ct64.Impl64
	skey [32]uint64 // I, J, L, 0
}

func newRoundB64(extractedKey *[extractedKeySize]byte) aesImpl {
	r := new(roundB64)
	for i := 0; i < 3; i++ {
		r.RkeyOrtho(r.skey[i*8:], extractedKey[i*16:])
	}

	return r
}

func (r *roundB64) Reset() {
	memwipeU64(r.skey[:])
}

func (r *roundB64) AES4(j, i, l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint64
	xorBytes4x16(j[:], i[:], l[:], src, dst[:])

	r.Load4xU32(&q, dst[:])
	r.Ortho(q[:])
	r.round(&q, r.skey[8:])  // J
	r.round(&q, r.skey[0:])  // I
	r.round(&q, r.skey[16:]) // L
	r.round(&q, r.skey[24:]) // zero
	r.Ortho(q[:])
	r.Store4xU32(dst[:], &q)

	memwipeU64(q[:])
}

func (r *roundB64) AES10(l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	var q [8]uint64
	xorBytes1x16(src, l[:], dst[:])

	r.Load4xU32(&q, dst[:])
	r.Ortho(q[:])
	for i := 0; i < 3; i++ {
		r.round(&q, r.skey[0:])  // I
		r.round(&q, r.skey[8:])  // J
		r.round(&q, r.skey[16:]) // L
	}
	r.round(&q, r.skey[0:]) // I
	r.Ortho(q[:])
	r.Store4xU32(dst[:], &q)

	memwipeU64(q[:])
}

func (r *roundB64) round(q *[8]uint64, k []uint64) {
	r.Sbox(q)
	r.ShiftRows(q)
	r.MixColumns(q)
	r.AddRoundKey(q, k)
}

func memwipeU64(s []uint64) {
	for i := range s {
		s[i] = 0
	}
}

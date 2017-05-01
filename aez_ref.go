// aez_ref.go - Generic fallback routines.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build !amd64,gccgo,appengine

package aez

func xorBytes1x16(a, b, dst []byte) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func xorBytes4x16(a, b, c, d []byte, dst *[blockSize]byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i] ^ c[i] ^ d[i]
	}
}

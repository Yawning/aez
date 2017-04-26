// aez_amd64.go - AMD64 specific routines.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!appengine

package aez

//go:noescape
func xorBytes16AMD64SSE2(a, b, dst *byte)

func xorBytes16(a, b, dst []byte) {
	// As stupid as this is, it's actually a decent performance boost,
	// even though the compiler probably should be able to optimize such
	// things.
	xorBytes16AMD64SSE2(&a[0], &b[0], &dst[0])
}

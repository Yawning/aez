// aez_ref.go - Generic fallback routines.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build !amd64,gccgo,appengine

package aez

func xorBytes16(a, b, dst []byte) {
	xorBytes(a, b, dst)
}

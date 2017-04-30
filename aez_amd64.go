// aez_amd64.go - AMD64 specific routines.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!appengine

package aez

//go:noescape
func cpuidAMD64(cpuidParams *uint32)

//go:noescape
func xorBytes1x16AMD64SSE2(a, b, dst *byte)

//go:noescape
func xorBytes3x16AMD64SSE2(a, b, c, dst *byte)

//go:noescape
func xorBytes4x16AMD64SSE2(a, b, c, d, dst *byte)

//go:noescape
func aes4AMD64AESNI(s, k *byte)

//go:noescape
func aes10AMD64AESNI(s, k *byte)

func xorBytes1x16(a, b, dst []byte) {
	xorBytes1x16AMD64SSE2(&a[0], &b[0], &dst[0])
}

func xorBytes3x16(a, b, c, dst *[blockSize]byte) {
	xorBytes3x16AMD64SSE2(&a[0], &b[0], &c[0], &dst[0])
}

func xorBytes4x16(a, b, c, d []byte, dst *[blockSize]byte) {
	xorBytes4x16AMD64SSE2(&a[0], &b[0], &c[0], &d[0], &dst[0])
}

type roundAESNI struct {
	keys [extractedKeySize]byte
}

func (rk *roundAESNI) Reset() {
	memwipe(rk.keys[:])
}

func (rk *roundAESNI) Rounds(block *[blockSize]byte, rounds int) {
	switch rounds {
	case 4:
		aes4AMD64AESNI(&block[0], &rk.keys[0])
	case 10:
		aes10AMD64AESNI(&block[0], &rk.keys[0])
	default:
		panic("aez: roundAesni.Rounds(): round count")
	}
}

func newRoundAESNI(extractedKey *[extractedKeySize]byte) aesImpl {
	rk := new(roundAESNI)
	copy(rk.keys[:], extractedKey[:])

	return rk
}

func supportsAESNI() bool {
	const (
		aesniBit   = 1 << 25
		osXsaveBit = 1 << 27
	)

	// Check to see if the OS knows how to save/restore XMM state.
	// CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1
	regs := [4]uint32{0x01}
	cpuidAMD64(&regs[0])
	if regs[2]&osXsaveBit == 0 {
		return false
	}

	// Check for AES-NI support.
	// CPUID.(EAX=01H, ECX=0H):ECX.AESNI[bit 25] = 1
	return regs[2]&aesniBit != 0
}

func init() {
	if supportsAESNI() {
		newAes = newRoundAESNI
	}
}

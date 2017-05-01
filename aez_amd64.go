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
func xorBytes4x16AMD64SSE2(a, b, c, d, dst *byte)

//go:noescape
func aezE4AMD64AESNI(j, i, l, k, s, dst *byte)

//go:noescape
func aezE10AMD64AESNI(l, k, s, dst *byte)

func xorBytes1x16(a, b, dst []byte) {
	xorBytes1x16AMD64SSE2(&a[0], &b[0], &dst[0])
}

func xorBytes4x16(a, b, c, d []byte, dst *[blockSize]byte) {
	xorBytes4x16AMD64SSE2(&a[0], &b[0], &c[0], &d[0], &dst[0])
}

type roundAESNI struct {
	keys [extractedKeySize]byte
}

func (r *roundAESNI) Reset() {
	memwipe(r.keys[:])
}

func (r *roundAESNI) E4(j, i, l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	aezE4AMD64AESNI(&j[0], &i[0], &l[0], &r.keys[0], &src[0], &dst[0])
}

func (r *roundAESNI) E10(l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	aezE10AMD64AESNI(&l[0], &r.keys[0], &src[0], &dst[0])
}

func newRoundAESNI(extractedKey *[extractedKeySize]byte) aesImpl {
	r := new(roundAESNI)
	copy(r.keys[:], extractedKey[:])

	return r
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

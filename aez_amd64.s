// +build !noasm
// Generated by PeachPy 0.2.0 from aez_amd64.py


// func cpuidAMD64(cpuidParams *uint32)
TEXT ·cpuidAMD64(SB),4,$0-8
	MOVQ cpuidParams+0(FP), R15
	MOVL 0(R15), AX
	MOVL 4(R15), CX
	CPUID
	MOVL AX, 0(R15)
	MOVL BX, 4(R15)
	MOVL CX, 8(R15)
	MOVL DX, 12(R15)
	RET

// func xorBytes1x16AMD64SSE2(a *uint8, b *uint8, dst *uint8)
TEXT ·xorBytes1x16AMD64SSE2(SB),4,$0-24
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	MOVQ dst+16(FP), CX
	MOVOU 0(AX), X0
	MOVOU 0(BX), X1
	PXOR X1, X0
	MOVOU X0, 0(CX)
	RET

// func xorBytes3x16AMD64SSE2(a *uint8, b *uint8, c *uint8, dst *uint8)
TEXT ·xorBytes3x16AMD64SSE2(SB),4,$0-32
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	MOVQ c+16(FP), CX
	MOVQ dst+24(FP), DX
	MOVOU 0(AX), X0
	MOVOU 0(BX), X1
	MOVOU 0(CX), X2
	PXOR X1, X0
	PXOR X2, X0
	MOVOU X0, 0(DX)
	RET

// func xorBytes4x16AMD64SSE2(a *uint8, b *uint8, c *uint8, d *uint8, dst *uint8)
TEXT ·xorBytes4x16AMD64SSE2(SB),4,$0-40
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	MOVQ c+16(FP), CX
	MOVQ d+24(FP), DX
	MOVQ dst+32(FP), DI
	MOVOU 0(AX), X0
	MOVOU 0(BX), X1
	MOVOU 0(CX), X2
	MOVOU 0(DX), X3
	PXOR X1, X0
	PXOR X3, X2
	PXOR X2, X0
	MOVOU X0, 0(DI)
	RET

// func aes4AMD64AESNI(s *uint8, k *uint8)
TEXT ·aes4AMD64AESNI(SB),4,$0-16
	MOVQ s+0(FP), AX
	MOVQ k+8(FP), BX
	PXOR X0, X0
	MOVOU 0(AX), X1
	MOVO 0(BX), X2
	MOVO 16(BX), X3
	MOVO 32(BX), X4
	AESENC X3, X1
	AESENC X2, X1
	AESENC X4, X1
	AESENC X0, X1
	MOVOU X1, 0(AX)
	PXOR X2, X2
	PXOR X3, X3
	PXOR X4, X4
	RET

// func aes10AMD64AESNI(s *uint8, k *uint8)
TEXT ·aes10AMD64AESNI(SB),4,$0-16
	MOVQ s+0(FP), AX
	MOVQ k+8(FP), BX
	MOVOU 0(AX), X0
	MOVO 0(BX), X1
	MOVO 16(BX), X2
	MOVO 32(BX), X3
	AESENC X1, X0
	AESENC X2, X0
	AESENC X3, X0
	AESENC X1, X0
	AESENC X2, X0
	AESENC X3, X0
	AESENC X1, X0
	AESENC X2, X0
	AESENC X3, X0
	AESENC X1, X0
	MOVOU X0, 0(AX)
	PXOR X1, X1
	PXOR X2, X2
	PXOR X3, X3
	RET

// func aezE4AMD64AESNI(j *uint8, i *uint8, l *uint8, k *uint8, s *uint8, dst *uint8)
TEXT ·aezE4AMD64AESNI(SB),4,$0-48
	MOVQ j+0(FP), AX
	MOVQ i+8(FP), BX
	MOVQ l+16(FP), CX
	MOVQ k+24(FP), DX
	MOVQ s+32(FP), DI
	MOVQ dst+40(FP), SI
	MOVOU 0(DI), X0
	MOVO 0(AX), X1
	MOVO 0(BX), X2
	MOVO 0(CX), X3
	PXOR X1, X0
	PXOR X3, X2
	PXOR X2, X0
	PXOR X4, X4
	MOVO 0(DX), X2
	MOVO 16(DX), X1
	MOVO 32(DX), X3
	AESENC X1, X0
	AESENC X2, X0
	AESENC X3, X0
	AESENC X4, X0
	MOVOU X0, 0(SI)
	PXOR X2, X2
	PXOR X1, X1
	PXOR X3, X3
	RET

// func aezE10AMD64AESNI(l *uint8, k *uint8, s *uint8, dst *uint8)
TEXT ·aezE10AMD64AESNI(SB),4,$0-32
	MOVQ l+0(FP), AX
	MOVQ k+8(FP), BX
	MOVQ s+16(FP), CX
	MOVQ dst+24(FP), DX
	MOVOU 0(CX), X0
	MOVOU 0(AX), X1
	PXOR X1, X0
	MOVO 0(BX), X2
	MOVO 16(BX), X3
	MOVO 32(BX), X1
	AESENC X2, X0
	AESENC X3, X0
	AESENC X1, X0
	AESENC X2, X0
	AESENC X3, X0
	AESENC X1, X0
	AESENC X2, X0
	AESENC X3, X0
	AESENC X1, X0
	AESENC X2, X0
	MOVOU X0, 0(DX)
	PXOR X2, X2
	PXOR X3, X3
	PXOR X1, X1
	RET

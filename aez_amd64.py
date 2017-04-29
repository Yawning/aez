#!/usr/bin/env python3
#
# To the extent possible under law, Yawning Angel has waived all copyright
# and related or neighboring rights to aez, using the Creative
# Commons "CC0" public domain dedication. See LICENSE or
# <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

#
# Dependencies: https://github.com/Maratyszcza/PeachPy
#
# python3 -m peachpy.x86_64 -mabi=goasm -S -o aez_amd64.s aez_amd64.py
#

from peachpy import *
from peachpy.x86_64 import *

cpuidParams = Argument(ptr(uint32_t))

with Function("cpuidAMD64", (cpuidParams,)):
    reg_params = registers.r15
    LOAD.ARGUMENT(reg_params, cpuidParams)

    MOV(registers.eax, [reg_params])
    MOV(registers.ecx, [reg_params+4])

    CPUID()

    MOV([reg_params], registers.eax)
    MOV([reg_params+4], registers.ebx)
    MOV([reg_params+8], registers.ecx)
    MOV([reg_params+12], registers.edx)

    RETURN()

a = Argument(ptr(const_uint8_t))
b = Argument(ptr(const_uint8_t))
c = Argument(ptr(const_uint8_t))
d = Argument(ptr(const_uint8_t))
dst = Argument(ptr(uint8_t))

with Function("xorBytes1x16AMD64SSE2", (a, b, dst)):
    reg_a = GeneralPurposeRegister64()
    reg_b = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_a, a)
    LOAD.ARGUMENT(reg_b, b)
    LOAD.ARGUMENT(reg_dst, dst)

    xmm_a = XMMRegister()
    xmm_b = XMMRegister()

    MOVDQU(xmm_a, [reg_a])
    MOVDQU(xmm_b, [reg_b])

    PXOR(xmm_a, xmm_b)

    MOVDQU([reg_dst], xmm_a)

    RETURN()

with Function("xorBytes3x16AMD64SSE2", (a, b, c, dst)):
    reg_a = GeneralPurposeRegister64()
    reg_b = GeneralPurposeRegister64()
    reg_c = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_a, a)
    LOAD.ARGUMENT(reg_b, b)
    LOAD.ARGUMENT(reg_c, c)
    LOAD.ARGUMENT(reg_dst, dst)

    xmm_a = XMMRegister()
    xmm_b = XMMRegister()
    xmm_c = XMMRegister()

    MOVDQU(xmm_a, [reg_a])
    MOVDQU(xmm_b, [reg_b])
    MOVDQU(xmm_c, [reg_c])

    PXOR(xmm_a, xmm_b)
    PXOR(xmm_a, xmm_c)

    MOVDQU([reg_dst], xmm_a)

    RETURN()

with Function("xorBytes4x16AMD64SSE2", (a, b, c, d, dst)):
    reg_a = GeneralPurposeRegister64()
    reg_b = GeneralPurposeRegister64()
    reg_c = GeneralPurposeRegister64()
    reg_d = GeneralPurposeRegister64()
    reg_dst = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_a, a)
    LOAD.ARGUMENT(reg_b, b)
    LOAD.ARGUMENT(reg_c, c)
    LOAD.ARGUMENT(reg_d, d)
    LOAD.ARGUMENT(reg_dst, dst)

    xmm_a = XMMRegister()
    xmm_b = XMMRegister()
    xmm_c = XMMRegister()
    xmm_d = XMMRegister()

    MOVDQU(xmm_a, [reg_a])
    MOVDQU(xmm_b, [reg_b])
    MOVDQU(xmm_c, [reg_c])
    MOVDQU(xmm_d, [reg_d])

    PXOR(xmm_a, xmm_b)
    PXOR(xmm_c, xmm_d)
    PXOR(xmm_a, xmm_c)

    MOVDQU([reg_dst], xmm_a)

    RETURN()

#
# Sigh.  PeachPy has "interesting" ideas of definitions for certain things,
# so just use the `zen` uarch, because it supports everything.
#

s = Argument(ptr(uint8_t))
k = Argument(ptr(const_uint8_t))

with Function("aes4AMD64AESNI", (s, k), target=uarch.zen):
    reg_s = GeneralPurposeRegister64()
    reg_k = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_s, s)
    LOAD.ARGUMENT(reg_k, k)

    xmm_state = XMMRegister()
    xmm_i = XMMRegister()
    xmm_j = XMMRegister()
    xmm_l = XMMRegister()
    xmm_zero = XMMRegister()

    PXOR(xmm_zero, xmm_zero)
    MOVDQU(xmm_state, [reg_s])
    MOVDQU(xmm_i, [reg_k])
    MOVDQU(xmm_j, [reg_k+16])
    MOVDQU(xmm_l, [reg_k+32])

    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_zero)

    MOVDQU([reg_s], xmm_state)

    RETURN()

with Function("aes10AMD64AESNI", (s, k), target=uarch.zen):
    reg_s = GeneralPurposeRegister64()
    reg_k = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_s, s)
    LOAD.ARGUMENT(reg_k, k)

    xmm_state = XMMRegister()
    xmm_i = XMMRegister()
    xmm_j = XMMRegister()
    xmm_l = XMMRegister()
    xmm_zero = XMMRegister()

    PXOR(xmm_zero, xmm_zero)
    MOVDQU(xmm_state, [reg_s])
    MOVDQU(xmm_i, [reg_k])
    MOVDQU(xmm_j, [reg_k+16])
    MOVDQU(xmm_l, [reg_k+32])

    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_i)
    AESENC(xmm_state, xmm_j)
    AESENC(xmm_state, xmm_l)
    AESENC(xmm_state, xmm_i)

    MOVDQU([reg_s], xmm_state)

    RETURN()

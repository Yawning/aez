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

a = Argument(ptr(const_uint8_t))
b = Argument(ptr(const_uint8_t))
dst = Argument(ptr(uint8_t))

with Function("xorBytes16AMD64SSE2", (a, b, dst)):
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

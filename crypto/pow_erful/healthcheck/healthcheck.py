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
import hashlib
import time
from binascii import unhexlify, hexlify


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

# ===

# follow this to download the bitcoin blockchain_headers
# https://bitcoin.stackexchange.com/questions/89552/bitcoin-block-headers-download?answertab=votes#tab-top
# or just use the one the person made and uploaded to google drive

lookup = {}
with open('/home/user/blockchain_headers','rb') as f:
    while True:
        block_header = f.read(80)
        if len(block_header) < 80:
            break
        first_hash = hashlib.sha256(block_header).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        if second_hash.endswith(b'\x00' * 8):
            lookup[first_hash[:2]] = first_hash[2:]
print(len(lookup), "hashes loaded")

context.log_level = 'debug'
tries = 0
while True:
    conn = remote('127.0.0.1', 1337)
    # we aren't using kctf base container, so pow is nonexistent
    #print(conn.recvuntil('== proof-of-work: '))
    #if conn.recvline().startswith(b'enabled'):
    #    handle_pow(conn)

    for _ in range(63):
        conn.recvline()
        conn.recvline()
        conn.recvline()
        request = unhexlify(conn.recvline().split(b' ')[1])
        if request not in lookup:
            # success probability is 64971/65536 (# hashes / 256^2) per entry
            # for 64 straight ones, (64971/65536)^64 = ~0.57
            print("Failed on request", request, "trying again")
            tries += 1
            break
        conn.sendline(hexlify(lookup[request]))
        conn.recvline()
        conn.recvline()
    else:
        break

    # don't hammer the server if we messed up importing
    time.sleep(1)
    # fail
    if tries > 10:
        exit(1)
# ===
exit(0)

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

import pwn
import time
import stockfish
from stockfish import Stockfish

stockfish = Stockfish("./stockfish")
stockfish.set_depth(17)
proc = pwn.remote("127.0.0.1", 1337)

# Lose times, parse # of wins
count = 0
while count != 100:  # Should work
    proc.sendline('f2')
    proc.sendline('f3')
    proc.sendline('g2')
    proc.sendline('g4')
    proc.recvuntil("You currently have ")
    line = proc.readline()
    count = int(line.split(b" ")[0])
    print(count, end="\r")


moves = """
d2
d4
c2
c4
h2
h4
h4
h5
g2
g4
g4
g5
g5
h6
c1
g5
h5
g6
""".strip().split()

pairs = [moves[i:i+2] for i in range(0, len(moves), 2)]

print(pairs)

for pair in pairs:
    proc.sendline(pair[0])
    proc.sendline(pair[1])
proc.recvuntil(b'Stockfish played b8c6')
buffer = ""
try:
    while True:
        fen = b''
        while b' w ' not in fen:
            buffer = proc.recvuntil("FEN: ")
            fen = proc.recvline().strip()
        print("Received FEN", fen)
        stockfish.set_fen_position(fen.decode())
        best_move = stockfish.get_best_move()
        print("We want to make the move:", best_move)
        proc.sendline(best_move[:2])
        proc.sendline(best_move[2:])
except EOFError:
    proc.recvline()
    proc.recvline()
    flag = proc.recvline()

print(flag)


if b'uiuctf' in flag:
    exit(0)
else:
    print('Error: Couldn\'nt find the flag in output.')
    print(flag)
    exit(1)

from pwn import *
from ctypes import c_uint32



def solve(challenge):
    challenge = c_uint32(challenge)
    for i in range(133):
        challenge.value ^= (challenge.value << 13)
        challenge.value ^= (challenge.value >> 17)
        challenge.value ^= (challenge.value << 5)

    return challenge.value

print("Response:", solve(int(input("Challenge: "))))

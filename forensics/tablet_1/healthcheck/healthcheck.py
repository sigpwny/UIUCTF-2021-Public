#!/usr/bin/env python3
import paramiko
import io
import hashlib

ssh = paramiko.client.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname='127.0.0.1',port=42069,username='red',password='********',key_filename='/home/user/id_rsa')
sftp = ssh.open_sftp()

file = io.BytesIO()
sftp.getfo('/srv/.../important_data.jpg', file)
buf = file.getvalue()
md5 = hashlib.md5(buf).hexdigest()
if "d7b522a0704e003d0aa1f84a5f79f733" == md5:
    exit(0)
else:
    exit(1)


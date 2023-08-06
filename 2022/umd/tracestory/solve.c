#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

int main(int argc, char *argv[])
{
    struct user_regs_struct regs;
    pid_t pid;

    unsigned long mov_rbp_rax = 0x401802;
    unsigned long filename_addr = 0x402011;

    if(argc < 2)
        exit(1);
    
    pid = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    // wait(NULL);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("rip: %llx\n", regs.rip);

    ptrace(PTRACE_POKETEXT, pid, filename_addr, 0x67616c66);

    ptrace(PTRACE_POKETEXT, pid, mov_rbp_rax, 0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, mov_rbp_rax+8, 0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, mov_rbp_rax+16, 0x9090909090909090);
    ptrace(PTRACE_POKETEXT, pid, mov_rbp_rax+24, 0xf789489090909090);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}

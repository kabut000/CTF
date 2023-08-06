# babynote  
最初に入力する値が`alloca`に渡される  
この値はshort型であるため65535(=0xffff)を入力すると-1と解釈される  
showで65535まで指定できるためlibcリークが出来る    
newでrbpが保存されているところを指定することで`main`終了時にrspがヒープのアドレスになりROPが出来る  
```
mov rsp, rbp
pop rbp  
```
```
0000| 0x7ffec7a5e960 --> 0x556d3bd10260 --> 0x41 ('A')
0008| 0x7ffec7a5e968 --> 0xffff3a240dfd 
0016| 0x7ffec7a5e970 --> 0x3533353536 ('65535')
0024| 0x7ffec7a5e978 --> 0xffff3a240e4d 
0032| 0x7ffec7a5e980 --> 0x7ffec7a5e960 --> 0x556d3bd10260 --> 0x41 ('A')
0040| 0x7ffec7a5e988 --> 0x9184f6358a2d5800 
0048| 0x7ffec7a5e990 --> 0x7ffec7a5e9b0 --> 0x556d3a240e00 (<__libc_csu_init>:  push   r15)     <- ここをヒープのアドレスにする  
0056| 0x7ffec7a5e998 --> 0x556d3a240dac (<main+35>:     mov    eax,0x0)
0064| 0x7ffec7a5e9a0 --> 0x7ffec7a5ea90 --> 0x1 
0072| 0x7ffec7a5e9a8 --> 0xffff000000000000 
0080| 0x7ffec7a5e9b0 --> 0x556d3a240e00 (<__libc_csu_init>:     push   r15)
0088| 0x7ffec7a5e9b8 --> 0x7f193c666b97 (<__libc_start_main+231>:       mov    edi,eax)
0096| 0x7ffec7a5e9c0 --> 0x2000000000 ('')
0104| 0x7ffec7a5e9c8 --> 0x7ffec7a5ea98 --> 0x7ffec7a608e0 ("/home/pwn/chall")
0112| 0x7ffec7a5e9d0 --> 0x100000000 
0120| 0x7ffec7a5e9d8 --> 0x556d3a240d89 (<main>:        push   rbp)
0128| 0x7ffec7a5e9e0 --> 0x0 
0136| 0x7ffec7a5e9e8 --> 0xb98dc7241b84182b 
0144| 0x7ffec7a5e9f0 --> 0x556d3a2408c0 (<_start>:      xor    ebp,ebp)
0152| 0x7ffec7a5e9f8 --> 0x7ffec7a5ea90 --> 0x1 
0160| 0x7ffec7a5ea00 --> 0x0 
0168| 0x7ffec7a5ea08 --> 0x0 
0176| 0x7ffec7a5ea10 --> 0xecaa3c27d404182b 
0184| 0x7ffec7a5ea18 --> 0xed65cba0d11a182b 
0192| 0x7ffec7a5ea20 --> 0x7ffe00000000 
--More--(25/32)
0200| 0x7ffec7a5ea28 --> 0x0 
0208| 0x7ffec7a5ea30 --> 0x0 
0216| 0x7ffec7a5ea38 --> 0x7f193ca468d3 (<_dl_init+259>:        add    r14,0x8)
0224| 0x7ffec7a5ea40 --> 0x7f193ca2c638 --> 0x7f193c7dee10 --> 0x8348535554415541           <- ここでlibc leak  
0232| 0x7ffec7a5ea48 --> 0x24130e0 
0240| 0x7ffec7a5ea50 --> 0x0 
0248| 0x7ffec7a5ea58 --> 0x0
```

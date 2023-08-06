# nimrev  
```
pwndbg> tele 0x7ffff7d540d0
00:0000│ rdx rsi 0x7ffff7d540d0 ◂— 0x18
01:0008│         0x7ffff7d540d8 ◂— 0x1c
02:0010│         0x7ffff7d540e0 ◂— 0x7b465443656b6143 ('CakeCTF{')
03:0018│         0x7ffff7d540e8 ◂— 0x336d3174336d3073 ('s0m3t1m3')
04:0020│         0x7ffff7d540f0 ◂— 0x7d435f74306e5f73 ('s_n0t_C}')
05:0028│         0x7ffff7d540f8 ◂— 0x0
... ↓            2 skipped
pwndbg> x/s 0x7ffff7d540e0
0x7ffff7d540e0: "CakeCTF{s0m3t1m3s_n0t_C}"
```
flag: `CakeCTF{s0m3t1m3s_n0t_C}`

# histogram   
`NaN`を入力すると`(short)ceil(weight / WEIGHT_STRIDE) - 1`が-1になる  
```
gdb-peda$ x/30gx 0x000000000404020
0x404020 <__isoc99_fscanf@got.plt>:     0x00007ffff7cdf320      0x0000000000401050
0x404030 <fclose@got.plt>:      0x0000000000401061      0x0000000000401070
0x404040 <printf@got.plt>:      0x0000000000401080      0x00007ffff7cfea90
0x404050 <exit@got.plt>:        0x00000000004010a0      0x00007ffff7eedc80
0x404060:       0x0000000000000000      0x0000000000000000
0x404070:       0x0000000000000000      0x0000000000000000
0x404080 <completed>:   0x0000000000000000      0x0000000000000000
0x404090:       0x0000000000000000      0x0000000000000000
0x4040a0 <map>: 0x0000000000000000      0x0000000000000000
```
`map`のそばにGOTがあるので書き換えられる  
`fclose`を`win`に書き換える  
flag: `ACSC{NaN_demo_iiyo}`  

- [writeup](https://github.com/IRS-Cybersec/ctfdump/tree/master/ACSC%202021/histogram)  
- [writeup](https://stdnoerr.github.io/ctf/2021/09/19/ACSC2021.html)

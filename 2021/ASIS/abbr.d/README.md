# ABBR  
```
$ ./abbr 
Enter text: aaw
Result: arbitrary address write
```
略語を入力することでBOFを起こせる  
入力バッファの下にTranslator構造体がある  
```
gdb-peda$ x/20gx 0x4ceb90+0x1000
0x4cfb90:       0x4141414141414141      0x0041414141414141
0x4cfba0:       0x0000000000000000      0x0000000000000021
0x4cfbb0:       0x0000000000401da5      0x00000000004ceba0      <-- 
0x4cfbc0:       0x0000000000001000      0x0000000000020441
```
```c
typedef struct Translator {
  void (*translate)(char*);
  char *text;
  int size;
} Translator;
```
translateを書き換える  
Stack pivotしてROP  
flag: `ASIS{d1d_u_kn0w_ASIS_1s_n0t_4n_4bbr3v14t10n}`  

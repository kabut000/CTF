# fables_of_aesop  
BOF -> FSOP  
書き込む領域の下にFILEポインタがある  
FILEポインタを偽装FILEポインタに書き換える  
vtableを偽装_IO_jump_t構造体に向ける   
```
+++++++++++++++++++++   <- buf  
偽装fp  
+++++++++++++++++++++  
偽装_IO_jump_t  
+++++++++++++++++++++   <- buf + 0x200  
buf  
+++++++++++++++++++++  
```
[参考1](https://github.com/theoremoon/InterKosenCTF2020-challenges/blob/master/pwn/fables_of_aesop/solution/solve.py)  
[参考2](https://hackmd.io/@Xornet/By-W6D74D)  

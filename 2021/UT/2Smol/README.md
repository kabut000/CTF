# 2Smol  
SROP  
`read`で0xfバイト読み込んでsyscallで`sigreturn`を呼び出す  
rspを`read`でシェルコードを書き込んだ領域に、ripを`main`にする  
[参考1](https://github.com/datajerk/ctf-write-ups/blob/master/utctf2021/smol/exploit.py)  
[参考2](https://hackmd.io/@imth/SROP)  

# Some Really Ordinary Program (Unsolved)  
SROP  
`read`で0xfバイト読み込んでsyscallで`sigreturn`を呼び出す  
rspを`read`でシェルコードを書き込んだ領域に、ripを`main`にする  
[参考1](https://github.com/datajerk/ctf-write-ups/tree/master/nahamconctf2021)  
[参考2](https://hackmd.io/@imth/SROP)  

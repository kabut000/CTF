# CArot  
BOFがあるがプロキシがあるため入力が1回のみ    
ROPで`system("cat flag.txt")`  
### ROP  
まず書き込み可能領域に`printf`のアドレスを置く  
オフセットを足して`system`のアドレスにする  
次に`scanf`で文字列`cat flag.txt`を`gif`に入れる  
RBPを`system`があるアドレスに、RDIを`gif`のアドレスにして`jmp qword ptr [rbp]`  
[参考](https://stdnoerr.github.io/ctf/2021/09/19/ACSC2021.html)  

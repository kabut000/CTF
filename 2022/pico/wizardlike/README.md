1. `gdb -n ./game`  
2. `(gdb) r`  
3. Ctrl+C  
4. `(gdb) i proc map`  
5. `(gdb) x/2g addr+0x1fe70`  
addrは4で表示されたアドレスの1番上の左  
addr+0x1fe70=現在位置のx座標  
addr+0x1fe74=現在位置のy座標  
addr+0x1fe7c=現在の階層    
6. `(gdb) set {int}addr+0x1fe70=x`  
`(gdb) set {int}addr+0x1fe74=y`  
`(gdb) set {int}addr+0x1fe7c=n`  
任意の位置と階層にいける  

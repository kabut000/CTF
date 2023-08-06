# babydriver  
SMEP有効  
2回open()して1回close()することでUAFになる  
/dev/ptmxをopen()することでtty_struct構造体を被せる  
tty_struct構造体のopsを書き換える  
write()したときにstack pivotでROPが起こるようにする  

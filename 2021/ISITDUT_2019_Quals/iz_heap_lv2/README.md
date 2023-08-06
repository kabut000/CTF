# iz_heap_lv2
名前の入力がなくなった  
Off By One  
```c
    read(0,param_1,(long)param_2);
    if (param_2 != 0) {
        *(undefined *)((long)param_1 + (long)param_2) = 0;
    }
```
unsorted binに繋いでlibc leak  
次に`malloc(0x18)`するとすでに確保されている領域を確保できる  
Double Freeして`__free_hook`を書き換える  

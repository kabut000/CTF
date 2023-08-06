# babynote
ヒープオーバーフロー  
真下のチャンクのfdを`__free_hook`にして次の`malloc`で確保  
`__free_hook`を書き換える  

<別解>  
最初のリークを使わない方法  
ヒープオーバーフローでtopとチャンクを偽装する  
topのサイズが小さいとabortする  
```c
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
```
0x420のチャンクをunsorted binに繋ぐ  
overlapされてるチャンクでlibc leak, Double Free    

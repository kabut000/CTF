# DeathNote  
libc 2.23  
fastbin attack  
unsorted binに繋ぎUAFでlibcをリーク  
`__malloc_hook`を書き換える  
`__malloc_hook`を-0x23ずらすと0x7fのチャンクとみなされる  
`malloc(0x60)`で`__malloc_hook - 0x13`が確保される  
[参考](https://hama.hatenadiary.jp/entry/2018/12/08/142437)  

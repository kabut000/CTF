# Popping Caps
回数制限7回  
最後に`malloc`が呼ばれる  
任意の領域を`free`できる  
0x3b0のチャンクを`free`してsizeをつくる  
tcacheの管理領域+0x40を`free` -> `malloc`で確保して`__malloc_hook`を書き込む  
次の`malloc(0x18)`で`__malloc_hook`を確保する  
Writeでは`read`で8文字読み込んでいるため改行すると失敗する  

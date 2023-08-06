# iz_heap_lv1
libc 2.27  
サイズとインデックスが無制限  
ヒープのポインタを格納している領域の下にnameの領域がある    
名前の入力で偽装チャンクと`free`するポインタを書き込む  
インデックスを指定することでDouble Free  
unsorted binに繋いでlibc leak  

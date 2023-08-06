# four function heap
libc 2.27  
heapをリーク  
Double Freeでtcacheの管理領域を確保  
カウンタをいじって`free`したときにunsorted binに繋がるようにする  
次に`malloc`したときにtcacheの管理領域を確保できるようにする  
確保したあとに`__free_hook`を書き込んで次に`malloc`したときに確保できるようにする  
unsorted binに繋がれるとfdとbkに値が書き込まれる -> カウンタの領域  

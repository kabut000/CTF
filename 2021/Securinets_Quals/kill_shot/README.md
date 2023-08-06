# kit shot
seccompが有効で`system("/bin/sh")`が使えない  
```
$ seccomp-tools dump ./kill_shot 
```
ROP  
`__free_hook`を`kill`で書き換える  
`read` -> `openat` -> `read` -> `write`  

[参考1](https://ptr-yudai.hatenablog.com/entry/2021/03/22/141505)  
[参考2](https://ctftime.org/writeup/26696)  
[参考3](https://thegoonies.github.io/2021/03/21/securinetctf-2021-killshot/)  


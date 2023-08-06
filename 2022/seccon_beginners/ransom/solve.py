enc_flag = b'\x2b\xa9\xf3\x6f\xa2\x2e\xcd\xf3\x78\xcc\xb7\xa0\xde\x6d\xb1\xd4\x24\x3c\x8a\x89\xa3\xce\xab\x30\x7f\xc2\xb9\x0c\xb9\xf4\xe7\xda\x25\xcd\xfc\x4e\xc7\x9e\x7e\x43\x2b\x3b\xdc\x09\x80\x96\x95\xf6\x76\x10'
randstr = 'rgUAvvyfyApNPEYg'
flag = b''

j = 0
k = 0
buf = [i for i in range(0x100)]
for i in range(0x100):
    k = buf[i] + j + ord(randstr[i%0x10])
    l = (k >> 0x1f) >> 0x18
    j = (k+l&0xff) - l
    buf[i], buf[j] = buf[j], buf[i]

j = 0
k = 0
for i in range(len(enc_flag)):
    j = j + 1 & 0xff
    k = buf[j] + k & 0xff
    buf[j], buf[k] = buf[k], buf[j]
    flag += bytes([enc_flag[i] ^ buf[(buf[j]+buf[k])&0xff]])
print(flag)

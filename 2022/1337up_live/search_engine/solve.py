from Crypto.Util.number import *

flag = ''
for n in [0x547b505537333331, 0x7230665f33733368, 0x3372615f7374346d, 0x7d216b633468775f]:
    b = long_to_bytes(n)
    flag += ''.join(list(reversed(b.decode())))
print(flag)

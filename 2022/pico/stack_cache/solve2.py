from Crypto.Util.number import *

flag = ''

for n in reversed("0x7d 0x37363765 0x63353532 0x5f597230 0x6d334d5f 0x50755f4e 0x34656c43 0x7b465443 0x6f636970".split()):
    b = long_to_bytes(int(n, 16))
    flag += ''.join(list(reversed(b.decode())))
print(flag)

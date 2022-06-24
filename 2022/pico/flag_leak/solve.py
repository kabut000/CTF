from Crypto.Util.number import *

flag = ''
for n in "0x7b465443.0x6b34334c.0x5f676e31.0x67346c46.0x6666305f.0x3474535f.0x365f6b63.0x33616561.0x7d633763".split('.'):
    b = long_to_bytes(int(n, 16))
    flag += ''.join(list(reversed(b.decode())))
print(flag)

from Crypto.Util.number import *

flag = ''
for n in [0x6d697b6674636873, 0x636172747369645f, 0x756f795f676e6974, 0x56183c000a7d]:
    b = long_to_bytes(n)
    flag += ''.join(list(reversed(b.decode())))
print(flag)

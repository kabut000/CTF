from Crypto.Util.Padding import pad

enc = "5a53c5be38edb11be0ad826e7495074b0bb8e163fd3e8f0085b76e79b47702c6"
iv = bytes.fromhex(enc[:32])
a = pad(b'fizzbuzz', 16)
b = pad(b'getflag', 16)
x = b''.join([bytes([i^j^k]) for i, j, k in zip(iv, a, b)])
print(x.hex()+enc[32:])

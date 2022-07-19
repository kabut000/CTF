from base64 import b64encode, b64decode

enc = open("./flag.enc", "rb").read()

ba = b64encode(b'CCTF{')
key_len = len(enc) // 8
baph = ''
s = b''
flag = ''

for b in ba.decode():
    if b.islower():
        baph += b.upper()
    else:
        baph += b.lower()

baph = baph.encode()
key = b''.join([bytes([x^y]) for x, y in zip(baph[:key_len], enc[:key_len])])

for i in range(len(enc)):
    s += bytes([enc[i]^key[i%key_len]])

for c in s.decode():
    if c.islower():
        flag += c.upper()
    else:
        flag += c.lower()

print(b64decode(flag.encode()))

from Crypto.Util.number import *

pt = 'A' * 32
pt = bytes.fromhex(pt)
enc = 'b491b268cb0024a22fca02ca65ec46a40e2b08d271ba9e189570b870df56fc1e'
enc = bytes.fromhex(enc)
k = b''.join([bytes([x^y]) for x, y in zip(enc, pt)])

enc = '765468a71ac1e86ada13c00fba2a88516d4f71a10af5fa67da13dc15a920b3667b6473ac0eddfd57e7539b55f7228e397b0320f104cebb3cf867af67c841eb09'
enc = bytes.fromhex(enc)
flag = b''.join([bytes([enc[i]^k[i%16]]) for i in range(len(enc))])
print(flag)

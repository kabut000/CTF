from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

privatekey = open("./privatekey.pem", "rb").read()
enc = open("./encrypted.bin", "rb").read()
key = RSA.importKey(privatekey)
c = PKCS1_OAEP.new(key)
flag = c.decrypt(enc)
print(flag)

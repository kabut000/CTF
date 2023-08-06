ciphertext = b'babda2b7a9bcbda68db38dbebda68dbdb48db9b7aba18dbfb6a2aaa7a3beb1a2bfb7b5a3a7afd8'

byte = int(ciphertext, 16).to_bytes(len(ciphertext)//2, 'big')
key = ord('h') ^ byte[0]
flag = b''.join([bytes([key ^ b]) for b in byte])
print(flag)

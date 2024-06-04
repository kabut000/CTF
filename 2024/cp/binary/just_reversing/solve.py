enc = open('./flag_enc.txt', 'rb').read()
flag = []

for c in enc:
    for x in range(0x21, 0x7e):
        if c == (x//16 + x%16*16):
            flag.append(x)
            break

print("".join([chr(c) for c in reversed(flag)]))

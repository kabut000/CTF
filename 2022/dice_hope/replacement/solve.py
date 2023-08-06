enc = open('output.txt').read()
enc_flag = enc.split('\n')[-2]
flag = 'hope{'
characters = set(enc) - {'\n'}
r = dict()

for i in range(len(flag)):
    r[flag[i]] = enc_flag[i]
r['}'] = enc_flag[-1]
print(r)
print(characters)
for k, v in r.items():
    enc = enc.replace(v, k)
# print(enc)

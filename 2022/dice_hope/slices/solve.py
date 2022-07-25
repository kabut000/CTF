flag = b'hope{' + b'*' * (32 - 6) + b'}'
flag = list(flag)

def f(s, x, y):
    j = 0
    for i in range(x, len(flag), y):
        flag[i] = s[j]
        j += 1

f(b'i0_tnl3a0', 5, 3)
f(b'{0p0lsl', 4, 4)
f(b'e0y_3l', 3, 5)
f(b'_vph_is_t', 6, 3)
f(b'ley0sc_l}', 7, 3)

print(b''.join([bytes([c]) for c in flag]))

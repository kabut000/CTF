
x = 0xc
for i in range(6):
    print(x, end=" ")
    x = (3 * x + 7) & 0xf

print()
    
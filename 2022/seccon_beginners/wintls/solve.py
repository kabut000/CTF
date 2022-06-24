s = "c4{fAPu8#FHh2+0cyo8$SWJH3a8X"
t = "tfb%s$T9NvFyroLh@89a9yoC3rPy&3b}"
flag = ""

i = 0
j = 0
for k in range(len(s)+len(t)):
    if k%3!=0 and k%5!=0:
        flag += t[i]
        i += 1
    else:
        flag += s[j]
        j += 1

print(flag)

A = matrix([[21,301,-9549,55692],[1,0,0,0],[0,1,0,0],[0,0,1,0]])   
B = A**19999997%(10**10000)
ans = B[0][0]*4+B[0][1]*3+B[0][2]*2+B[0][3]*1   
print(ans)
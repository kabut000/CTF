# 2021_emulator
以下で範囲外アクセスできる。  
```c
        case 0x36:
            emu->memory[get_hl(emu)] = get_mem_pc(emu);
            break;
```
H, Lレジスタを調整すると`instructions`を書き換えられる  
`system`のpltは`0x4010d0`なので2バイト書き換えればよさそう  
後はがんばって`registers`に`/bin/sh`を書き込んでおしまい  
flag: `ctf4b{Y0u_35c4p3d_fr0m_3mul4t0r}`  

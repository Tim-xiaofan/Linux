//修改系统调用参数
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_EAX etc */
#include <sys/user.h>
#include <sys/syscall.h> /* SYS_write */
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define long_size  sizeof(long)
#define BUF_SIZE 128

void putdata(pid_t child, long addr,
            char *str, int len)
{   char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) 
    {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
                    addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) 
    {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
                    addr + i * 4, data.val);
    }
}

static void 
getdata(pid_t child, long addr, char *str, int len) 
{   
    char *laddr;
    int i, j;
    union u 
    {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) 
    {
        data.val = ptrace(PTRACE_PEEKDATA,
                    child, addr + i * 8,
                    NULL);
        if(data.val == -1)
          if(errno) {
              perror("ptace (PTRACE_PEEKDATA)");
          }
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) 
    {
        data.val = ptrace(PTRACE_PEEKDATA,
                    child, addr + i * 8,
                    NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

int main(int ac, char * av[]) 
{
    pid_t child;
    struct user_regs_struct regs;
    char code[] = {0xcd,0x80,0xcc,0x00,0,0,0,0};
    char backup[8];
    long inst;

    if(ac != 2) {
        printf("Usage: %s <pid to be traced>\n",
                    av[0]);
        exit(1);
    }
    child = atoi(av[1]);

    ptrace(PTRACE_ATTACH, child, NULL, NULL);
    wait(NULL);
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    inst = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
    printf("child: EIP:0x%llx INST: 0x%lx\n", regs.rip, inst);

    /* Copy instructions into a backup variable */
    getdata(child, regs.rip, backup, 7);
    /* Put the breakpoint */
    putdata(child, regs.rip, code, 7);
    /* Let the process continue and execute the int 3 instruction */
    ptrace(PTRACE_CONT, child, NULL, NULL);

    wait(NULL);
    printf("Press Enter to continue ptraced process.\n");
    getchar();
    putdata(child, regs.rip, backup, 7);
    ptrace(PTRACE_SETREGS, child, NULL, &regs);

    ptrace(PTRACE_CONT, child, NULL, NULL);
    ptrace(PTRACE_DETACH, child, NULL, NULL);
    return 0;
}

//读取系统调用参数
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_EAX etc */
#include <sys/user.h>
#include <sys/syscall.h> /* SYS_write */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BUF_SIZE 128
#define FAKE_OUT "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"

const int long_size = sizeof(long);

void reverse(char *str)
{   int i, j;
    char temp;
    for(i = 0, j = strlen(str) - 2;
                i <= j; ++i, --j) {
        temp = str[i];
        str[i] = str[j];
        str[j] = temp;
    }
}

void show_bytes(char * bytes)
{
    int i;
    for(i = 0; i < long_size; ++i)
      printf("%c ", bytes[i]);
    printf("\n");
}

void getdata(pid_t child, long addr,
            char *str, int len)
{   char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    //printf("len = %d, j = %d\n", len, j);
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA,
                    child, addr + i * long_size,
                    NULL);
        if(data.val == -1)
        {
            perror("ptrace(PTRACE_PEEKDATA)");
            return;
        }
        memcpy(laddr, data.chars, long_size);
        //printf("bytes[%d] : ", i);
        //show_bytes(data.chars);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA,
                    child, addr + i * long_size,
                    NULL);
        if(data.val == -1)
        {
            perror("ptrace(PTRACE_PEEKDATA)");
            return;
        }
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

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
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
                    addr + i * long_size, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
                    addr + i * long_size, data.val);
    }
}

int main(int ac, char * av[]) 
{
    pid_t child;
    long orig_rax;
    int status, iscalling = 0;
    struct user_regs_struct regs;
    char str[BUF_SIZE];
#ifdef __x86_64__
    printf("RAX = %d\n", RAX);
#else
    print("not x86_64\n");
#endif

    child = fork();
    if(child == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);//告诉内当前进程正在被追踪
        execl("/bin/ls", "ls", "-l", "-h", NULL);
    }
    else 
    {
        while(1) 
        {
            wait(&status);
            /** WIFEXITED函数(宏)用来检查子进程是被ptrace暂停的还是准备退出*/
            if(WIFEXITED(status))
              break;
            /** 参数将寄存器的值读取到结构体user_regs_struct*/
            orig_rax = ptrace(PTRACE_PEEKUSER,
                        child, 8 * ORIG_RAX,
                        NULL);
            if(orig_rax == SYS_write) {
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                if(!iscalling) {
                    iscalling = 1;
                    printf("SYS_write call with %lld, %lld, %lld\n",
                                regs.rdi, regs.rsi, regs.rdx);
                    getdata(child, regs.rsi, str,
                                regs.rdx);
                    printf("origin = %s", str);
                    reverse(str);
                    strcpy(str, FAKE_OUT);
                    putdata(child, regs.rsi, str,
                                strlen(FAKE_OUT) + 1);
                }
                else {
                    printf("SYS_write call return %lld\n", regs.rax);
                    iscalling = 0;
                }
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }
    return 0;
}

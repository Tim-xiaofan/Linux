//读取系统调用参数
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_EAX etc */
#include <sys/user.h>
#include <sys/syscall.h> /* SYS_write */
#include <unistd.h>
#include <stdio.h>

int main(int ac, char * av[]) 
{
    pid_t child;
    long orig_rax;
    int status, iscalling = 0;
    struct user_regs_struct regs;
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

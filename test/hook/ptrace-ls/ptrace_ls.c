#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_RAX etc */

int main(int ac, char *av[])
{   
    pid_t child;
    long orig_rax;
    child = fork();
    if(child == 0) 
    {
        printf("enter child\n");
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }
    else 
    { 
        printf("enter parent\n");
        wait(NULL);
        orig_rax = ptrace(PTRACE_PEEKUSER,
                    child, 8 * ORIG_RAX,
                    NULL);
        printf("The child made a "
                    "system call %ld\n", orig_rax);
        ptrace(PTRACE_CONT, child, NULL, NULL);//让子进程继续运行
    }
    return 0;
}

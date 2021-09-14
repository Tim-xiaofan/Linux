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

int main(int ac, char * av[])
{
    int i;
    for(i = 0;i < 100; ++i) 
    {
        printf("My(pid = %d) counter: %d\n",getpid(),  i);
        sleep(2);
    }
    return 0;
}

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
#define BUF_SIZE 128

int main(int ac, char * av[])
{
    int i;
    char buf[BUF_SIZE];

    for(i = 0; i < 1000; ++i) 
    {
        sprintf(buf, "My(pid = %d) counter: %d\n",getpid(),  i);
        write(1, buf, strlen(buf) + 1);
        sleep(2);
    }
    return 0;
}

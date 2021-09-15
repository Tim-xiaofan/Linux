//读取系统调用参数
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_EAX etc */
#include <sys/user.h>
#include <sys/syscall.h> /* SYS_write */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int ac, char * av[]) 
{	
	pid_t child;
	struct user_regs_struct regs;
	long orig_rax, err;
	int iscalling = 0, iscalling1 = 0;

	if(ac != 2) 
	{
		printf("Usage: %s <pid to be traced>\n",
					av[0]);
		exit(1);
	}
	child = atoi(av[1]);

	//ptrace(PTRACE_ATTACH, child, NULL, NULL);
	//wait(NULL);
	//ptrace(PTRACE_GETREGS, child, NULL, &regs);
	//inst = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
	//printf("child: EIP:0x%llx INST: 0x%lx\n", regs.rip, inst);

	///* Copy instructions into a backup variable */
	//getdata(child, regs.rip, backup, 7);
	///* Put the breakpoint */
	//putdata(child, regs.rip, code, 7);
	///* Let the process continue and execute the int 3 instruction */
	//ptrace(PTRACE_CONT, child, NULL, NULL);

	//wait(NULL);
	//printf("Press Enter to continue ptraced process.\n");
	//getchar();
	//putdata(child, regs.rip, backup, 7);
	//ptrace(PTRACE_SETREGS, child, NULL, &regs);

	//ptrace(PTRACE_CONT, child, NULL, NULL);
	//ptrace(PTRACE_DETACH, child, NULL, NULL);
	err = ptrace(PTRACE_ATTACH, child, NULL, NULL);
	if(err != 0)
	{
		perror("ptrace PTRACE_ATTACH");
		exit(errno);
	}
	printf("success attach.\n");
	while(1) 
	{
		printf("before wait\n");
		wait(NULL);
		/** 参数将寄存器的值读取到结构体user_regs_struct*/
		orig_rax = ptrace(PTRACE_PEEKUSER,
					child, 8 * ORIG_RAX,
					NULL);
		if(orig_rax == SYS_write)
		{
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			if(err != 0)
			{
				perror("ptrace PTRACE_GETREGS");
				exit(errno);
			}
			if(!iscalling) 
			{
				iscalling = 1;
				printf("SYS_write call with %lld, %lld, %lld\n",
							regs.rdi, regs.rsi, regs.rdx);
			}
			else 
			{
				printf("SYS_write call return %lld\n", regs.rax);
				iscalling = 0;
			}
		}
		else if(orig_rax == SYS_read)
		{
			if(!iscalling1) {
				iscalling1 = 1;
				printf("SYS_read call with %lld, %lld, %lld\n",
							regs.rdi, regs.rsi, regs.rdx);
			}
			else 
			{
				printf("SYS_read call return %lld\n", regs.rax);
				iscalling1 = 0;
			}
		}
		else
		{
			printf("orig_rax = %ld\n", orig_rax);
		}
		err = ptrace(PTRACE_CONT, child, NULL, NULL);
		if(err != 0)
		{
			perror("ptrace PTRACE_CONT");
			exit(errno);
		}
	}//while
	
	ptrace(PTRACE_CONT, child, NULL, NULL);
	ptrace(PTRACE_DETACH, child, NULL, NULL);
	
	return 0;
}

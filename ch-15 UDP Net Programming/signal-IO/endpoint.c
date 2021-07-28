#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

#define BUF_SIZE 1500
#define PORT 1100

static bool force_quit = false;
static int nqueue = 0;

static void signal_handle(int signum)
{
	if(signum == SIGIO)
	{
		nqueue++;
	}
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
	printf("signum=%d, nqueue=%d\n", signum, nqueue);//打印信号值 
}

//static void setsockopt_err(int num)
//{
//	switch(num)
//	{
//		case EBADF:printf("EBADF\n");break;
//		case EFAULT:printf("EFAULT\n");break;
//		case EINVAL:printf("EINVAL\n");break;
//		case ENOPROTOOPT:printf("ENOPROTOOPT\n");break;
//		case ENOTSOCK:printf("ENOTSOCK\n");break;
//		default:fprintf(stderr, "Unknown error\n");
//	}
//}

int main(int ac, char * av[])
{
	struct sockaddr_in localaddr, remoteaddr;
	int sockfd, ret;
	socklen_t addrlen;
	char buf[BUF_SIZE];
	time_t tm;
	struct sigaction action;
	sigset_t newmask, oldmask;

	if(ac == 1)
	{
		printf("Usage : ./program mode ##args\n");
		exit(EXIT_FAILURE);
	}

	/** 设置SIGINI的处理函数*/
	memset(&action, 0, sizeof(action));
	action.sa_handler = signal_handle;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);//面向消息的UDP
	if(socket < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if(strcmp("server", av[1]) == 0)
	{
		printf("mode is server\n");
		if(ac != 4)
		{
			close(sockfd);
			printf("Usage : ./program client localaddr localport\n");
			exit(EXIT_FAILURE);
		}

		localaddr.sin_family = AF_INET;
		localaddr.sin_addr.s_addr = inet_addr(av[2]);//本机IP
		localaddr.sin_port = htons(atoi(av[3]));
		ret = bind(sockfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr));
		if(ret < 0)
		{
			perror("bind");
			close(sockfd);
			exit(errno);
		}
		printf("bind(%s:%d)\n",
					inet_ntoa(localaddr.sin_addr),
					ntohs(localaddr.sin_port));

		/** 设置SIGIO信号的处理函数*/
		memset(&action, 0, sizeof(action));
		action.sa_handler = signal_handle;
		action.sa_flags = 0;
		sigaction(SIGIO, &action, NULL);

		/** 设置socket的拥有者*/
		ret = fcntl(sockfd, F_SETOWN, getpid());
		if(ret == -1)
		{
			perror("fcntl(F_SETOWN)");
			close(sockfd);
			exit(errno);
		}
		/** 设置socket为信号驱动型*/
		int on = 1;
		ret = ioctl(sockfd, FIOASYNC, &on);
		if(ret == -1)
		{
			perror("ioctl(FIOASYNC)");
			close(sockfd);
			exit(errno);
		}

		addrlen = sizeof(struct sockaddr_in);
		sigemptyset(&oldmask);
		sigemptyset(&newmask);
		sigaddset(&newmask, SIGIO);
		printf("Get ready.\n");
		while(!force_quit)
		{
			sigprocmask(SIG_BLOCK, &newmask, &oldmask);//设置当前进程的阻塞信号
			while(nqueue == 0 && !force_quit)sigsuspend(&oldmask);//等待信号时进行休眠
			ret = recvfrom(sockfd,
						buf,
						BUF_SIZE - 1,
						MSG_DONTWAIT,
						(struct sockaddr *) &remoteaddr, 
						&addrlen);
			if(ret == -1 && errno == EAGAIN)
			{
				//perror("recvfrom ");
				nqueue = 0;
			}
			else
			{
				printf("recvfrom (%s:%d), len=%d : %s\n",
							inet_ntoa(remoteaddr.sin_addr),
							ntohs(remoteaddr.sin_port), ret, buf);
			}
			sigprocmask(SIG_SETMASK, &oldmask, NULL);//修改进程阻塞的信号
		}
	}
	else if(strcmp("client", av[1]) == 0)
	{
		printf("mode is client\n");
		if(ac != 4)
		{
			printf("Usage : ./program client remoteaddr remoteport\n");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		remoteaddr.sin_family = AF_INET;
		remoteaddr.sin_addr.s_addr = inet_addr(av[2]);//remoteaddr
		remoteaddr.sin_port = htons(atoi(av[3]));
		addrlen = sizeof(struct sockaddr_in);
		
		while(!force_quit)
		{
			bzero(buf, BUF_SIZE);
			tm = time(NULL);
			sprintf(buf, "%s", ctime(&tm));//broadcast time
			ret = sendto(sockfd,
						buf,
						strlen(buf) + 1,
						0,
						(const struct sockaddr *) &remoteaddr,
						addrlen);
			if(ret <= 0)
			{
				perror("sendto");
				break;
			}
			else
			{
				printf("sendto (%s:%d), len=%d : %s\n",
							inet_ntoa(remoteaddr.sin_addr),
							ntohs(remoteaddr.sin_port), ret, buf);
			}
			usleep(100);
		}
	}
	else
	{
		fprintf(stderr, "unkown mode %s\n", av[1]);
	}
	close(sockfd);
	return 0;
}

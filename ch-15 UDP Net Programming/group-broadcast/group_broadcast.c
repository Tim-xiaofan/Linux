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
#include <netdb.h>

#define BUF_SIZE 1024
#define PORT 10000

static bool force_quit = false;

/* On all other architectures */
//int pipe(int pipefd[2]);
void signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

static void setsockopt_err(int num)
{
	switch(num)
	{
		case EBADF:printf("EBADF\n");break;
		case EFAULT:printf("EFAULT\n");break;
		case EINVAL:printf("EINVAL\n");break;
		case ENOPROTOOPT:printf("ENOPROTOOPT\n");break;
		case ENOTSOCK:printf("ENOTSOCK\n");break;
		default:fprintf(stderr, "Unknown error\n");
	}
}

int main(int ac, char * av[])
{
	struct sockaddr_in localaddr, remoteaddr;
	int sockfd, ret;
	socklen_t addrlen;
	char buf[BUF_SIZE];
	time_t tm;
	struct ip_mreq im;
	//struct hostent *group;
	//struct in_addr ia;

	if(ac == 1)
	{
		printf("Usage : ./program mode ##args\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, signal_handle);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);//面向消息的UDP
	if(socket < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if(strncmp("recv", av[1], 4) == 0)
	{
		printf("mode is recv\n");
		if(ac != 4)
		{
			printf("Usage : ./program recv groupaddr localaddr\n");
			exit(EXIT_FAILURE);
		}

		/** 设置组播地址*/
		bzero(&im, sizeof(struct ip_mreq));
		im.imr_multiaddr.s_addr = inet_addr(av[2]);
		im.imr_interface.s_addr = inet_addr(av[3]);
		printf("localaddr is %s\n", inet_ntoa(im.imr_interface));
		printf("groupaddr is %s\n", inet_ntoa(im.imr_multiaddr));
		/* 设置发送组播消息的源主机的地址信息 */
		/** 将自己的IP加入组播地址*/
		ret = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &im, sizeof(struct ip_mreq));	
		if(ret == -1)
		{
			perror("setsockopt(IP_ADD_MEMBERSHIP)");
			setsockopt_err(errno);
			exit(errno);
		}

		localaddr.sin_family = AF_INET;
		localaddr.sin_addr.s_addr = htonl(INADDR_ANY);//本机IP
		localaddr.sin_port = htons(PORT);
		ret = bind(sockfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr));
		if(ret < 0)
		{
			perror("bind");
			exit(errno);
		}
		printf("bind(%s:%d)\n", 
					inet_ntoa(localaddr.sin_addr), 
					ntohs(localaddr.sin_port));

		addrlen = sizeof(struct sockaddr_in);
		while(!force_quit)
		{
			ret = recvfrom(sockfd, 
						buf,
						BUF_SIZE - 1,
						0,
						(struct sockaddr *) &remoteaddr, &addrlen);
			if(ret <= 0)
			{
				perror("recvfrom ");
				break;
			}
			else
			{
				printf("recvfrom (%s:%d), len=%d : %s\n", 
							inet_ntoa(remoteaddr.sin_addr), 
							ntohs(remoteaddr.sin_port), ret, buf);
			}
		}
	}
	else if(strncmp("send", av[1], 4) == 0)
	{
		printf("mode is send\n");
		if(ac != 4)
		{
			printf("Usage : ./program send groupaddr localaddr\n");
			exit(EXIT_FAILURE);
		}

		remoteaddr.sin_family = AF_INET;
		remoteaddr.sin_addr.s_addr = inet_addr(av[2]);//group addr
		remoteaddr.sin_port = htons(PORT);
		addrlen = sizeof(struct sockaddr_in);
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(PORT + 1);
		localaddr.sin_addr.s_addr = inet_addr(av[3]);//localaddr

		ret = bind(sockfd, (const struct sockaddr *)&localaddr, sizeof(struct sockaddr));
		if(ret < 0)
		{
			perror("bind2");
			exit(errno);
		}
		printf("bind(%s:%d)\n", 
					inet_ntoa(localaddr.sin_addr), 
					ntohs(localaddr.sin_port));

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

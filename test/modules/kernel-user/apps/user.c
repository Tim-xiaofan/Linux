#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include "ku_ioctl.h"

#define BUF_SIZE    128
#define IP          "127.0.0.1"
#define PORT        7788

static char buf[256];
static bool force_quit          = false;
static const char * devfile     = NULL;
static int sockfd               = -1;

static void 
signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

/** devfile ip port*/
static int 
mod_config(int ac, char *av[])
{
	pid_t pid;
	int ret, tmpfd, fd;

	if(ac != 5)
	{
		fprintf(stderr, "mod_config : devfile ip port pid fd\n");
		return -1;
	}
	
	fd = open(av[0], O_RDWR);
	if(fd < 0)
	{
		perror("open");
		exit(errno);
	}

	//set pid
	pid = atoi(av[3]);
	ret = ioctl(fd, IOCSPID, pid);
	if(ret == -1)
	{
		perror("ioctl IOCSPID");
		close(fd);
		return -1;
	}
	printf("set pid : %d\n", pid);

	//read pid
	ret = ioctl(fd, IOCGPID, &pid);
	if(ret == -1)
	{
		perror("ioctl IOCGPID");
		close(fd);
		return -1;
	}
	printf("read pid : %d\n", pid);

	sockfd = atoi(av[4]);
	ret = ioctl(fd, IOCSFD, sockfd);
	if(ret == -1)
	{
		perror("ioctl IOCFD");
		close(fd);
		return -1;
	}
	printf("set sockfd : %d\n", sockfd);

	//read sockfd
	ret = ioctl(fd, IOCGFD, &tmpfd);
	if(ret == -1)
	{
		perror("ioctl IOCGFD");
		close(fd);
		return -1;
	}
	printf("read sockfd : %d\n", tmpfd);

	//set IP
	uint32_t ip = inet_addr(av[1]);
	struct in_addr in;
	ret = ioctl(fd, IOCSIP, ip);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl IOCSIP");
		return -1;
	}
	printf("set ip : %s\n", av[1]);

	ret = ioctl(fd, IOCGIP, &ip);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl IOCGIP");
		return -1;
	}
	in.s_addr = ip;
	printf("read ip : %s\n", inet_ntoa(in));
	//set port
	uint16_t port = htons(atoi(av[2])); 
	ret = ioctl(fd, IOCSPORT, port);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl IOCSPORT");
		return -1;
	}

	ret = ioctl(fd, IOCGPORT, &port);
	if(ret == -1)
	{
		close(fd);
		perror("ioctl IOCGPORT");
		return -1;
	}
	printf("read port : %u\n", ntohs(port));
	close(fd);
	return 0;
}

int main(int ac, char *av[])
{
	int ret, devfd;
	time_t tm;

	if(ac < 2)
	{
		printf("Usage : ./program devfile\n");
		return -1;
	}

	signal(SIGINT, signal_handle);

	devfile = av[1];
	printf("devfile = %s\n", devfile);
	devfd = open(devfile, O_RDWR);
	if(devfd < 0)
	{
		perror("open");
		exit(errno);
	}

	//config mod
	--ac;
	++av;
	if(mod_config(ac, av) == -1)
	{
		fprintf(stderr, "mod_config failed\n");
		goto done;
	}

	while(!force_quit)
	{
		tm = time(NULL);
		sprintf(buf, "fake time : %s", ctime(&tm));
		ret = write(devfd, buf, strlen(buf) + 1);
		if(ret < 0){
			fprintf(stderr, "ret = %d\n", ret);
			perror("write");
			break;
		}
		usleep(1000000);
	}

	ret = read(devfd, buf, BUF_SIZE);
	if(ret < 0){
		perror("read");
	}
	else
	{
		printf("data from kernel : %s\n",buf);
	}

done:
	close(devfd);
	close(sockfd);
	printf("done.\n");
	return 0;
}

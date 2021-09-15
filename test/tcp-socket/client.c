#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<stdint.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<time.h>
#define MAXLINE 4096
#define LISTEN_PORT 2333

int main(int argc, char** argv)
{
	int   sockfd, n;
	char  recvline[MAXLINE], sendline[MAXLINE];
	struct sockaddr_in  servaddr;
	time_t tt;

	if( argc != 3){
		printf("usage: ./client <ipaddress> <port>\n");
		return 0;
	}

	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
		return 0;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(argv[2]));/** remote port */
	if( inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0){
		printf("inet_pton error for %s\n",argv[1]);
		return 0;
	}

	if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){
		printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
		return 0;
	}

	printf("send msg to server: \n");
	//fgets(sendline, 4096, stdin);
	while(1)
	{
		tt = time(NULL);
		sprintf(sendline, "%s", ctime(&tt));
		fprintf(stdout, "send : %s", sendline);
		if( send(sockfd, sendline, MAXLINE, 0) < 0){
			printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
			break;
		}
		usleep(50);
	}
	close(sockfd);
	return 0;
}

/*server.c*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <stdbool.h>

#define MAX_BUFFER 256
#define MY_PORT_NUM 2222
#define LOCALTIME_STREAM 0
#define GMT_STREAM 1

static bool force_quit = false;

void signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

int main(int ac, char * av[])
{
	int listenSock, connSock, ret, addrlen;
	struct sockaddr_in servaddr, remoteaddr;
	struct sctp_initmsg initmsg;
	char buffer[MAX_BUFFER + 1];
	time_t currentTime;

	if(ac != 3)
	{
		printf("Usage : ./prog <addr> <port>\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, signal_handle);
	addrlen = sizeof(struct sockaddr_in);

	/* Create SCTP TCP-Style Socket */
	listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if(listenSock < 0)
	{
		perror("socket ");
		exit(errno);
	}

	/* Accept connections from any interface */
	bzero((void *)&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;//ip
	servaddr.sin_addr.s_addr = inet_addr(av[1]);
	servaddr.sin_port = htons(atoi(av[2]));
	/* Bind to the wildcard address (all) and MY_PORT_NUM */
	ret = bind(listenSock,
				(struct sockaddr *)&servaddr, sizeof(servaddr));
	if(ret < 0)
	{
		perror("bind ");
		exit(errno);
	}

	/* Specify that a maximum of 5 streams will be available per socket */
	memset(&initmsg, 0, sizeof(initmsg) );
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 4;
	ret = setsockopt( listenSock, IPPROTO_SCTP, SCTP_INITMSG,
				&initmsg, sizeof(initmsg));
	if(ret < 0)
	{
		perror("bind ");
		exit(errno);
	}

	/* Place the server socket into the listening state */
	listen(listenSock, 5);

	/* Await a new client connection */
	printf("Waiting a connection...\n");
	connSock = accept(listenSock,
				(struct sockaddr *)&remoteaddr, (socklen_t *)&addrlen);
	/* New client socket has connected */
	printf("Got a connection from (%s : %d)\n", 
				inet_ntoa(remoteaddr.sin_addr), ntohs(remoteaddr.sin_port));
	printf("pid sockfd : %d, %d\n", getpid(), connSock);
	
	/* Server loop... */
	while (!force_quit)
	{
		/* Grab the current time */
		currentTime = time(NULL);
		/* Send local time on stream 0 (local time stream) */
		snprintf(buffer, MAX_BUFFER, "%s\n", ctime(&currentTime));
		printf("server:buffer = %s\n", buffer);
		ret = sctp_sendmsg(connSock,
					(void *)buffer,
					(size_t)strlen(buffer),
					(struct sockaddr*)NULL, 0, 0, 0, LOCALTIME_STREAM, 0, 0);
		if(ret < 0)
		{
			perror("sctp_sendmsg");
			break;
		}
		/* Send GMT on stream 1 (GMT stream) */
		snprintf(buffer, MAX_BUFFER, "%s\n",
					asctime(gmtime(&currentTime)));
		ret = sctp_sendmsg(connSock,
					(void *)buffer, 
					(size_t)strlen(buffer),
					(struct sockaddr*)NULL,//This value is the destination address of the message
					0,//This value is the length of the destination address
					htonl(18),//This value is the application-specified payload protocol identifier
					0,//flags
					GMT_STREAM,//stream number
					0,//time to live
					0);//context
		if(ret < 0)
		{
			perror("sctp_sendmsg");
			break;
		}
		//sleep(1);
	}
	close(listenSock);
	close(connSock);
	return 0;
}


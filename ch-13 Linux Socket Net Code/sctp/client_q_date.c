/** sctp client*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <stdbool.h>

#define MAX_BUFFER 256
#define MY_PORT_NUM 2222
#define LOCALTIME_STREAM 0
#define GMT_STREAM 1


static bool force_quit = false;
static const char *record_file = "/tmp/pid_sock.txt";

void signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

int 
recored(const char * filename, pid_t pid, int sockfd)
{
	FILE *fp = fopen(filename, "w");
	if(!fp)
	{
		fprintf(stderr, "fopen \"%s\" failed : %s\n", 
					filename, strerror(errno));
		return -1;
	}
	fprintf(fp, "pid sockfd : %d %d\n", pid, sockfd);
	fclose(fp);
	return 0;
}

static void 
recvbuf_ck(int fd)
{
	int recvbuf_sz, ret;
	socklen_t size;
	ret = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recvbuf_sz, &size);
	if(ret == -1)
	{
		perror("getsockopt SO_RCVBUF");
	}
	else
	{
		printf("socket recvbuf_sz = %d\n", recvbuf_sz);
	}
}



int main(int ac, char *av[])
{
	int connSock, in, flags, ret;
	struct sockaddr_in servaddr;
	struct sctp_sndrcvinfo sndrcvinfo;
	struct sctp_event_subscribe events;
	char buffer[MAX_BUFFER + 1];

	if(ac != 3)
	{
		printf("Usage : ./prog <addr> <port>\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, signal_handle);

	/* Create an SCTP TCP-Style Socket */
	connSock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if(connSock == -1)
	{
		perror("socket err\n");
		exit(errno);
	}
	ret = recored(record_file, getpid(), connSock);
	if(ret == -1)
	{
		close(connSock);
		exit(EXIT_FAILURE);
	}
	printf("origin : \n");
	recvbuf_ck(connSock);

	/* Specify the peer endpoint to which we'll connect */
	bzero((void *)&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(av[1]);
	servaddr.sin_port = htons(atoi(av[2]));

	/* Enable receipt of SCTP Snd/Rcv Data via sctp_recvmsg */
	memset((void *)&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;
	ret = setsockopt(connSock, SOL_SCTP, SCTP_EVENTS,
				(const void *)&events, sizeof(events));

	/* Connect to the server */
	ret = connect(connSock, (struct sockaddr *)&servaddr, sizeof(servaddr));
	//printf("press enter to cotinue.\n");
	//getchar();
	if(ret == -1)
	{
		perror("connect");
		exit(errno);
	}
	printf("connect success to %s:port %d, sock %d\n", 
				inet_ntoa(servaddr.sin_addr), 
				ntohs(servaddr.sin_port), connSock);

	if(ret == -1)
	{
		perror("setsockopt ");
		exit(errno);
	}

	/* Expect two messages from the peer */
	while(!force_quit)
	{
		in = sctp_recvmsg(connSock, (void *)buffer, sizeof(buffer),
					(struct sockaddr *)NULL, 0,
					&sndrcvinfo, &flags);
		/* Null terminate the incoming string */
		if(in ==  -1)
		{
			perror("sctp_recvmsg");
			recvbuf_ck(connSock);
			break;
		}
		if(in == 0)
		{
			continue;
		}
		buffer[in] = 0;
		if (sndrcvinfo.sinfo_stream == LOCALTIME_STREAM)
		{
			printf("(Local) %s\n", buffer);
		}
		else if (sndrcvinfo.sinfo_stream == GMT_STREAM)
		{
			printf("(GMT  ) %s\n", buffer);
		}
	}
	/* Close our socket and exit */
	close(connSock);
	return 0;
}

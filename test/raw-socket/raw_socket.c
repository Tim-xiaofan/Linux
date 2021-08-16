#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#define BUF_SIZE 1600
#define SRC_PORT 1100
#define DST_PORT 2200

static bool force_quit = false;

static void 
signal_handle(int signum)
{
	if(signum == SIGINT)
	{
		printf("Preparing to quit...\n");
		force_quit = true;
	}
}

int main(int ac, char * av[])
{
	int sfd, myRwnd, ch = 10 * 0xFFFF, ret;
	char packet[BUF_SIZE];
	socklen_t opt_size;
	struct tcphdr *tcp = NULL;
	struct sigaction action;

	/** 设置SIGINI的处理函数*/
	memset(&action, 0, sizeof(action));
	action.sa_handler = signal_handle;
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);

	if((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
	{
		perror("socket");
		exit(errno);
	}


	struct sockaddr_in remote; // remote address

	//struct iphdr *ip = (struct iphdr *) packet;

	opt_size=sizeof(myRwnd);
	if (getsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)&myRwnd, &opt_size) < 0) {
		perror("getsockopt: SO_RCVBUF failed");
		exit(errno);
	}
	printf("receive buffer size initially is %d bytes\n", myRwnd);

	if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, (void*)&ch, sizeof(ch)) < 0) {
		perror("setsockopt: SO_RCVBUF failed");
		exit(errno);
	}
	printf("set receive buffer size to : %d bytes\n",ch);

	ch = IP_PMTUDISC_DO;
	if (setsockopt(sfd, IPPROTO_IP, IP_MTU_DISCOVER, (char *) &ch, sizeof(ch)) < 0) {
		perror("setsockopt: IP_PMTU_DISCOVER failed");
		exit(errno);
	}
	opt_size=sizeof(myRwnd);
	if (getsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)&myRwnd, &opt_size) < 0) {
		perror("getsockopt: SO_RCVBUF failed");
		myRwnd = -1;
		exit(errno);
	}
	printf("receive buffer size finally is %d bytes\n", myRwnd);

	tcp = (struct tcphdr *) packet; // tcp header
	remote.sin_family = AF_INET; // family
	remote.sin_addr.s_addr = inet_addr("10.10.0.69"); // destination ip
	remote.sin_port = htons(DST_PORT); // destination port

	memset(packet, 0, BUF_SIZE); // set packet to 0

	tcp->source = htons(SRC_PORT); // source port
	tcp->dest = htons(DST_PORT); // destination port
	tcp->seq = htons(random()); // inital sequence number
	tcp->ack_seq = htons(0); // acknowledgement number
	tcp->ack = 0; // acknowledgement flag
	tcp->syn = 1; // synchronize flag
	tcp->rst = 0; // reset flag
	tcp->psh = 0; // push flag
	tcp->fin = 0; // finish flag
	tcp->urg = 0; // urgent flag
	tcp->check = 0; // tcp checksum
	tcp->doff = 5; // data offset

	printf("Press enter to start\n");
	getchar();

	while(!force_quit)
	{
		if((ret = sendto(sfd, 
							packet,
							sizeof(struct tcphdr), 
							0, 
							(struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0)
		{ // send packet
			printf("Error: Can't send packet : %d %d %s !\n", ret, errno, strerror(errno));
			break;
		}
		else printf("%d bytes is sent\n", ret);
		usleep(100000);
	}
	close(sfd);
	return 0;
}

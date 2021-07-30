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

#define BUF_SIZE 1024

int main(int ac, char * av[])
{
	int inet_sock, i; 
	struct ifreq ifr; 
	inet_sock = socket(AF_INET, SOCK_DGRAM, 0);//创建 socket以获取地址信息 
	char mac[32];

	if(ac != 2)
	{
		fprintf(stdout, "Usage:./program devname\n");
		exit(EXIT_FAILURE);
	}
	//eth0 为接口名，本机必须有一个这样的接口 
	strcpy(ifr.ifr_name, av[1]);
	if(ioctl(inet_sock, SIOCGIFADDR, &ifr)< 0) //获取接口IP信息 
	  perror ("ioct1");
	printf("ips : %s\n", inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr));

	if(ioctl(inet_sock, SIOCGIFHWADDR, &ifr)< 0) //获取接口MAC信息 
	  perror ("ioct1");
	for (i=0; i<6;i++) //输出 MAC 信息
	  sprintf(mac+3*i,"%02x:",(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	mac[17]='\0';
	printf ("mac addr is: %s\n", mac);
	return 0;
}

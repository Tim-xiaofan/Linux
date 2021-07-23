//Udp_group_recv.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>


int main(int argc,char *argv[])
{	
	int socked=socket(AF_INET,SOCK_DGRAM,0);  
	char group[16]="224.0.0.88";
	char group_1[16]="224.0.0.66";
	if(socked<0)
	{
		perror("socket failed!");
		return 2;
	}
	
	struct sockaddr_in local_addr;
	memset(&local_addr,0,sizeof(local_addr));
	
	local_addr.sin_family=AF_INET;
	local_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	local_addr.sin_port=htons(8888);
	
	int ret = bind(socked,(struct sockaddr*)&local_addr,sizeof(local_addr));
	if(ret<0)
	{
		perror("bind failed !");
		return 3;
	}
	
	struct ip_mreq mreq; // Multicast address structure
	mreq.imr_multiaddr.s_addr=inet_addr(group);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	
	ret=setsockopt(socked,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq));
	if(ret<0)
	{
		perror("setsockopt failed !");
		return 3;
	}
	else
	{
		printf("setsockopt success\n");		
	}
	mreq.imr_multiaddr.s_addr=inet_addr(group_1);
	ret=setsockopt(socked,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq));
	if(ret<0)
	{
		perror("setsockopt_1 failed !");
		return 3;
	}
	else
	{
		printf("setsockopt_1 success\n");		
	}
	char buf[1024];
	int length=0;
	struct sockaddr_in sender;
	int sender_len=sizeof(sender);
 	while(1)
	{
		memset(buf, 0, sizeof(buf));  
		length=recvfrom(socked, buf, sizeof(buf), 0, (struct sockaddr*)&sender, (socklen_t *)&sender_len);
		buf[length]='\0';
		printf("%s %d : %s\n",inet_ntoa(sender.sin_addr),ntohs(sender.sin_port),buf);
	}
	setsockopt(socked, IPPROTO_IP, IP_DROP_MEMBERSHIP,&mreq, sizeof(mreq));
	close(socked);
	return 0;
}

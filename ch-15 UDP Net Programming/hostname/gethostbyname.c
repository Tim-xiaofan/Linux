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

static void 
print_hostent(const struct hostent *hp)
{
	int i;
	printf("\033[33mOfficial name :\033[0m %s\n", hp->h_name);
	printf("\033[33mAliases name :\033[0m \t");
	for(i = 0; hp->h_aliases[i]; ++i)
	  printf("%s ", hp->h_aliases[i]);
	printf("\n");
	printf("\033[33mType:\033[0m\t\t%s\n",hp->h_addrtype == AF_INET? "AF_INET":"AF_INET6");
	printf("\033[33mAddresses :\033[0m \t");
	if(hp->h_addrtype == AF_INET)
	  for(i = 0; hp->h_addr_list[i]; ++i)
		printf("%s ", inet_ntoa(*(struct in_addr *)hp->h_addr_list[i]));
	printf("\n");
}

int main(int ac, char * av[])
{
	struct hostent *hp;
	
	if(ac == 1)
	{
		printf("Usage : ./program hostname\n");
		exit(EXIT_FAILURE);
	}

	hp = gethostbyname(av[1]);
	if(!hp)
	{
		fprintf(stderr,"\033[33mgethostbyname :\033[0m\033[31m %s\033[0m\n",hstrerror(h_errno));
		exit(h_errno);
	}
	print_hostent(hp);
	printf("\033[31mThis text is red \033[0mThis text has default color\n");
	return 0;
}


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int ac, char * av[]) 
{
	size_t ret;
	printf("Calling the recvfrom() function...\n");

	ret = recvfrom(1, "send", strlen("send") + 1, 0, NULL, NULL);
	if (ret == -1) 
	{
		perror("recvfrom");
		exit(errno);
	}

	printf("recvfrom succeeded\n");

	return 0;
}

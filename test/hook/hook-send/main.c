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
	printf("Calling the send() function...\n");

	ret = send(1, "send", strlen("send") + 1, 0);
	if (ret == -1) 
	{
		perror("send");
		exit(errno);
	}

	printf("send succeeded\n");

	return 0;
}

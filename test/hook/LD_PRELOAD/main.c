#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

int main(int ac, char * av[]) 
{
	printf("Calling the fopen() function...\n");

	FILE *fp = fopen("test.txt", "r");
	if (!fp) 
	{
		perror("fopen");
		exit(errno);
	}

	printf("fopen() succeeded\n");
	fclose(fp);

	return 0;
}

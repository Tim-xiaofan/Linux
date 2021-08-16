#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int ac, char * av[])
{
	FILE * fp;
	char buf[128];

	fp  = fopen("./test.txt", "r");
	if(!fp) 
	{
		perror("fopen");
		exit(errno);
	}
	fgets(buf, 128, fp);
	printf("%s\n", buf);
	fgets(buf, 128, fp);
	printf("%s\n", buf);
	return 0;
}

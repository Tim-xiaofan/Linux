#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char *av[])
{
	printf("start...\n");
	
	struct mallinfo bfmalloc = mallinfo();
	printf("bfmalloc: %d\n", bfmalloc.uordblks);
	
	int *p = (int *)malloc(10);
	if (!p) {
		printf("allocation error...\n");
		exit(1);
	}

	struct mallinfo afmalloc  = mallinfo();
	printf("afmalloc: %d\n", afmalloc.uordblks);


	free(p);
	struct mallinfo fmalloc = mallinfo();
	printf("fmalloc: %d\n", fmalloc.uordblks);

	printf("done...\n");
	return 0;
}

#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

size_t send(int fd, const void * buf, size_t len, int flags) 
{
	printf("In our own send\n");

	size_t (*original_send)(int, const void *, size_t, int);
	original_send = dlsym(RTLD_NEXT, "send");
	return (*original_send)(fd, buf, len, flags);
}

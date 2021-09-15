#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>

/**
 * ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
 * */

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	printf("In our own recvfrom\n");

	size_t (*original_recvfrom)(int, void *, size_t, int, struct sockaddr * , socklen_t *);
	original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	return (*original_recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}

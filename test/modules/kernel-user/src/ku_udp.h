#ifndef _KU_UDP
#define _KU_UDP
#include <net/udp.h>

int ku_udp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
int ku_udp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);

#endif

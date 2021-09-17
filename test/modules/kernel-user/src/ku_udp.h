#ifndef _KU_UDP
#define _KU_UDP
#include <net/udp.h>

typedef int (*udp_recvmsg_t)(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
//extern udp_recvmsg_t old_udp_recvmsg;;
extern struct proto_ops new_udp_ops;
extern const struct proto_ops *old_udp_ops;

int ku_udp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len);
int ku_udp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);

#endif

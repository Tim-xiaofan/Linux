#include <linux/aio.h>
#include <net/sock.h>
#include <linux/socket.h>

//typedef int (*sctp_recvmsg_t)(struct kiocb *, struct socket *, struct msghdr *, size_t, int); 
//typedef int (*sctp_recvmsg_t)(struct sock *sk, struct msghdr *msg, size_t len,int noblock, int flags, int *addr_len);
//typedef int (*sctp_recvmsg_t)(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len);
typedef int (*sctp_recvmsg_t)(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
//extern sctp_recvmsg_t old_sctp_recvmsg;
extern struct proto_ops new_sctp_ops;
extern const struct proto_ops *old_sctp_ops;

int ku_sctp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);

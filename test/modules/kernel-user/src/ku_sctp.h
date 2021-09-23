#ifndef _KU_SCTP_H
#define _KU_SCTP_H
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
#define SCTP_MAX_PDU 1600 
#define SCTP_MAX_ASSOC 4

struct ku_sctp_message
{
    int len;
    char pdu[SCTP_MAX_PDU];
};

struct ku_sctp_ops
{
    struct proto_ops new_sctp_ops;
    const struct proto_ops *old_sctp_ops;
};

struct ku_sctpops_list
{
    int count;
    struct ku_sctp_ops list[SCTP_MAX_ASSOC];
};

extern struct ku_sctpops_list ku_sctpops_list;
extern const struct proto_ops *origin_sctp_ops;

int ku_sctp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
int ku_sctp_init(void);

#endif

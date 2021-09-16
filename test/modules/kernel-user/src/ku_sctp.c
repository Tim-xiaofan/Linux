#include <net/sctp/structs.h>
#include <net/sctp/sctp.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <net/ipv6.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <linux/module.h>
#include "ku_sctp.h"


sctp_recvmsg_t sctp_recvmsg		= NULL;

//int ku_udp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
int ku_sctp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	printk("my sctp_recvmsg\n");
	//return -1;
	//return udp_recvmsg(iocb, sock->sk, msg, len, flags & MSG_DONTWAIT, flags, &msg->msg_namelen);
	return sctp_recvmsg(iocb, sock, msg, len,  flags);
	//return sctp_recvmsg(iocb, sk, msg, len, noblock, flags, addr_len);
}

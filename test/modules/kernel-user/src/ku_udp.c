#include <linux/module.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp_states.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/netfilter.h>
#include <linux/route.h>
#include <linux/mroute.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/compat.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/transp_v6.h>
#endif
#include <net/ip_fib.h>

#include <linux/errqueue.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include "ku_udp.h"

//udp_recvmsg_t old_udp_recvmsg		= NULL;
struct proto_ops new_udp_ops;
const struct proto_ops *old_udp_ops	= NULL;

int ku_udp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	printk("my udp_sendmsg\n");
	if(old_udp_ops == NULL)
	{
        printk(KERN_INFO "old_udp_ops not set\n");
		return -EAGAIN;
	}
	return old_udp_ops->sendmsg(iocb, sock, msg, len);
}

int ku_udp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	printk("my udp_recvmsg\n");
	if(old_udp_ops == NULL)
	{
        printk(KERN_INFO "old_udp_ops not set\n");
		return -EAGAIN;
	}
	//return __udp_recvmsg(iocb, sock->sk, msg, len, flags & MSG_DONTWAIT, flags, &msg->msg_namelen);
	return old_udp_ops->recvmsg(iocb, sock, msg, len,  flags);
}

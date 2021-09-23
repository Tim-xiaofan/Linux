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
#include <linux/kfifo.h>
#include <linux/spinlock.h>
#include "ku_sctp.h"

#define MAX_PKTS 8 * 64


extern int ep_work;

struct ku_sctpops_list ku_sctpops_list;
const struct proto_ops *origin_sctp_ops = NULL;

static int inited = 0;

/* for deferred fb unref's: */
typedef int elem_t;
DECLARE_KFIFO_PTR(ku_sctpmsg_list, elem_t);
static spinlock_t ku_sctpmsg_list_lock;

int ku_sctpmsg_put(const elem_t * e)
{
   return  kfifo_in_spinlocked(&ku_sctpmsg_list, e, 1,
                                &ku_sctpmsg_list_lock);
}

int ku_sctpmsg_get(elem_t * e)
{
    return kfifo_out_spinlocked(&ku_sctpmsg_list, e, 1,
                &ku_sctpmsg_list_lock);
}

int ku_sctp_init(void)
{
    int error, i, j;
    printk(KERN_INFO "ku_sctp_init\n");
    if(inited)
    {
        printk(KERN_ALERT "ku_sctp_init : ku_sctpmsg_list is not NULL\n");
        return -1;
    }

    for(i = 0; i < SCTP_MAX_ASSOC; ++i)
      ku_sctpops_list.list[i].old_sctp_ops = NULL;
    error = kfifo_alloc(&ku_sctpmsg_list, MAX_PKTS, GFP_KERNEL);
    if(error)
    {
        printk(KERN_ERR "ku_sctp_init: kfifo_alloc failed\n");
        return error;
    }

    for(i = 0; i < 15; ++i)
    {
        if(ku_sctpmsg_put(&i))
        {
            printk(KERN_INFO "put i = %d\n", i);
        }
        else
        {
            printk(KERN_ALERT "put failed\n");
            break;
        }
    }

    for(i = 0; i < 15; ++i)
    {

        if(!ku_sctpmsg_get(&j))
        {
            printk(KERN_ERR "ku_sctp_init: kfifo_get failed\n");
            break;
        }
        else
        {
            printk(KERN_INFO "get j = %d\n", j);
        }
    }
    inited = 1;
    spin_lock_init(&ku_sctpmsg_list_lock);
    printk(KERN_INFO "ku_sctp_init finished\n");
    return 0;
}

//int ku_udp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
int ku_sctp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
    if(ep_work || true)
    {
        printk("my sctp_recvmsg\n");
        if(origin_sctp_ops == NULL)
        {
            printk(KERN_INFO "origin_sctp_ops is not set\n");
            return -EAGAIN;
        }
        return origin_sctp_ops->recvmsg(iocb, sock, msg, len,  flags);
    }
    else
    {
        return origin_sctp_ops->recvmsg(iocb, sock, msg, len, flags);
    }
}

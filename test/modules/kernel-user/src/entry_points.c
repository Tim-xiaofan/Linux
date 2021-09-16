/* simple kernel module: hello
 * Licensed under GPLv2 or later
 * */
#include <linux/fdtable.h>
#include <net/sctp/sctp.h>
#include <linux/kallsyms.h>
#include "entry_points.h"
#include "ku_udp.h"
#include "ku_sctp.h"

#define BUF_SIZE 1600

static char write_buf[BUF_SIZE];
static pid_t ep_pid                     = 0;
static int ep_fd                        = 0;
static uint32_t ep_ip                   = 0;
static uint16_t ep_port                 = 0;
static struct task_struct* ep_task      = NULL;
static struct files_struct* ep_files    = NULL;
static struct file* ep_file             = NULL;
static struct socket* ep_socket         = NULL;
extern sctp_recvmsg_t sctp_recvmsg;

static struct socket *find_sock_by_pid_fd(pid_t pid, int fd, int *err);
static struct task_struct * get_task_by_pid(int pid);
static struct files_struct* get_files_by_task(struct task_struct * task);
static struct file * get_file_by_file_fd(struct files_struct * files, int fd);

int 
ep_open(struct inode *node, struct file *fp)
{
	printk(KERN_INFO "ep open\n");
	return 0;
}

int 
ep_release(struct inode *node, struct file *fp)
{
	printk(KERN_INFO "ep release\n");
	return 0;
}

ssize_t 
ep_read(struct file *fp, char __user *buf, size_t size, loff_t * offset)
{
    int uncopied;
    static const char * msg2user = "kernel_user";//11 bytes
    /*将内核空间的数据copy到用户空间*/
    uncopied = copy_to_user(buf, msg2user, strlen(msg2user) + 1);
    if(uncopied)
    {
        printk(KERN_ERR "read : %d byte(s) not copy_to_user\n", uncopied);
        return -EFAULT;
    }
    return strlen(msg2user) + 1;
}

ssize_t 
ep_write(struct file *fp, const char __user *buf, size_t size, loff_t * offset)
{
	struct idr *idp;
    int uncopied, err, ret;
    size_t len; 
    size_t tolen;
    struct socket *sock;
	struct sock *sk;
    struct msghdr outmsg;
    struct kvec iov;
    struct sockaddr_in to;
	static struct proto_ops ops;
	sctp_recvmsg_t recvmsgp = NULL;

	idp = (void*)kallsyms_lookup_name("sctp_assocs_id");
	if(!idp)
	{
		printk(KERN_ALERT "cannot find symble \"sctp_assocs_id\"\n");
	}
	else
	{
		printk(KERN_INFO "ipd : layers=%d\n", idp->layers);
	}

    /*将用户空间的数据copy到内核空间*/
    len = (BUF_SIZE > size) ? size : BUF_SIZE;
    uncopied = copy_from_user(write_buf, buf, len);
    if(uncopied != 0)//未复制的非零(byte)
    {
        printk(KERN_ERR "write : %d byte(s) not copy_from_user\n", uncopied);
        return -EFAULT;
    }
    printk(KERN_INFO "copied to kernel : len=%ld, %s\n", len, write_buf);
    sock = find_sock_by_pid_fd(ep_pid, ep_fd, &err);
    if(!sock)
    {
        printk(KERN_ALERT "find_sock_by_pid_fd failed : "
                    "pid=%d, fd=%d, err=%d\n", 
                    ep_pid, ep_fd, err);
        return -ENXIO;
    }
	sk = sock->sk;
    printk(KERN_INFO "found socket : type=%d, proto-name=%s, family=%d, flags=%ld\n", 
                sock->type, sk->__sk_common.skc_prot->name, sock->ops->family, sock->flags);
	
	if(sock->ops->family == AF_INET && sock->sk->sk_protocol == IPPROTO_SCTP)
	{
		sctp_recvmsg = sock->ops->recvmsg;
		recvmsgp = sctp_recvmsg; 
		ops = *sock->ops;
		ops.sendmsg = ku_udp_sendmsg;
		ops.recvmsg = recvmsgp;
		sock->ops = &ops;
		ret = 0;
	}
	else
	{
		ops = *sock->ops;
		ops.sendmsg = ku_udp_sendmsg;
		ops.recvmsg = ku_udp_recvmsg;
		sock->ops = &ops;

		memset(&outmsg, 0, sizeof(outmsg));
		memset(&iov, 0, sizeof(iov));
		memset(&to, 0, sizeof(to));
		tolen = sizeof(to);

		to.sin_family = AF_INET;
		to.sin_addr.s_addr = ep_ip;
		to.sin_port = ep_port;

		outmsg.msg_name = (void *)&to;
		outmsg.msg_namelen = tolen;
		outmsg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

		iov.iov_base = (void *)write_buf;
		iov.iov_len = len;

		ret = kernel_sendmsg(sock, &outmsg, &iov, 1, iov.iov_len);
		if(ret < iov.iov_len)
		{
			printk(KERN_ALERT "kernel_sendmsg err : ret=%d, len=%ld\n",
						ret, iov.iov_len);
		}
	}
    return ret;
}

long 
ep_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	printk(KERN_INFO "ep ioctl\n");

    switch(cmd)
    {
        case IOCSPID:
            ep_pid = arg;
            printk(KERN_INFO "ep ioctl set pid : %d\n", ep_pid);
            break;
        case IOCGPID:
            *(pid_t *)arg  = ep_pid;
            printk(KERN_INFO "ep ioctl get pid : %d\n", ep_pid);
            break;
        case IOCSFD:
            ep_fd = arg;
            printk(KERN_INFO "ep ioctl set fd : %d\n", ep_fd);
            break;
        case IOCGFD:
            *(int *)arg = ep_fd;
            printk(KERN_INFO "ep ioctl get fd : %d\n", ep_fd);
            break;
        case IOCSIP:
            ep_ip = arg;
            printk(KERN_INFO "ep ioctl set ip : %08x\n", ep_ip);
            break;
        case IOCGIP:
            *(uint32_t *)arg = ep_ip;
            printk(KERN_INFO "ep ioctl get ip : %08x\n", ep_ip);
            break;
        case IOCSPORT:
            ep_port = arg;
            printk(KERN_INFO "ep ioctl set port : %04x\n", ep_port);
            break;
        case IOCGPORT:
            *(uint16_t *)arg = ep_port;
            printk(KERN_INFO "ep ioctl get port : %04x\n", ep_port);
            break;
        default:
            printk(KERN_INFO "ep ioctl invalid cmd : %d", cmd);
            return -EINVAL;
    }
	return 0;
}


static struct socket *
find_sock_by_pid_fd(pid_t pid, int fd, int *err)
{
    ep_task = get_task_by_pid(pid);
    if(!ep_task)
    {
        printk(KERN_ALERT "get_task_by_pid faild, pid = %d\n", pid);
        return NULL;
    }
    printk(KERN_INFO "task->on_cpu = %d\n", ep_task->on_cpu);
    
    ep_files = get_files_by_task(ep_task);
    if(!ep_files)
    {
        printk(KERN_ALERT "get_files_by_task failed\b");
        return NULL;
    }

    ep_file = get_file_by_file_fd(ep_files, fd);
    if(!ep_file)
    {
        printk(KERN_ALERT "get_file_by_file_fd failed\b");
        return NULL;
    }

    ep_socket = sock_from_file(ep_file, err);
    return ep_socket;
}

static struct task_struct * 
get_task_by_pid(int pid)
{
    struct task_struct * task;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task)
      get_task_struct(task);
    rcu_read_unlock();
    return task;
}

static struct files_struct* 
get_files_by_task(struct task_struct * task)
{
    struct files_struct * files;
    task_lock(task);
    files = task->files;
    task_unlock(task);
    return files;
}

static struct file * 
get_file_by_file_fd(struct files_struct * files, int fd)
{
    struct file * file;
    rcu_read_lock();
    file = fcheck_files(files, fd);
    rcu_read_unlock();
    return file;
}

/* simple kernel module: hello
 * Licensed under GPLv2 or later
 * */
#include <linux/fdtable.h>
#include <net/sctp/sctp.h>
#include <linux/kallsyms.h>
#include <linux/task_work.h>
#include <linux/fsnotify.h>
#include <linux/eventpoll.h>
#include <linux/fs.h>
#include "entry_points.h"
#include "ku_udp.h"
#include "ku_sctp.h"

#define BUF_SIZE 1600

static char write_buf[BUF_SIZE];
//static pid_t ep_pid                         = 0;
//static int ep_fd                            = 0;
//static uint32_t ep_ip                       = 0;
//static uint16_t ep_port                     = 0;
static int ep_default_link                  = 0;
int ep_work                                 = 0;

#define MAX_FILTER_NUM 10
#define MAX_FILTER_SZ  32

struct ep_configs
{
    int filter_ct, ref;
    char *filters[MAX_FILTER_NUM];
    struct ku_configs ku_cfgs;
};

static struct ep_configs ep_cfgs;
static int ep_del_filter(int index);
static void ep_show_filter(void);

struct task_info
{
    struct task_struct *task;
    struct files_struct *files;
    struct file *file;
};
typedef struct task_info task_info_t;

static struct socket *find_sock_by_pid_fd(pid_t pid, int fd, int *err, task_info_t * task_info);
static struct task_struct * get_task_by_pid(int pid);
static struct files_struct* get_files_by_task(struct task_struct * task);
static struct file * get_file_by_files_fd(struct files_struct * files, int fd);
static struct files_struct * ep_get_files_struct(struct task_struct *task);
//static void ep_lock(task_info_t * task_info);
static void ep_unlock(task_info_t * task_info);
static int ep_replace(void);

static void ep_put_files_struct(struct files_struct *files);
static void ep_fput(struct task_struct * task, struct file * file);
static void ep_put_task_struct(struct task_struct * task);
#define ep_p(x) ep_lock((x))
#define ep_v(x) {\
    /*ep_put_files_struct((x)->files);*/\
    /*fput((x)->file);*/\
    /*ep_unlock((x));*/\
    ep_put_task_struct((x)->task);\
    /*printk(KERN_INFO "ep_v is called\n");*/\
}
#define files_unlock(x) spin_unlock(&(x)->file_lock)
#define file_unlock(x) spin_unlock(&(x)->f_lock)

static void print_configs(const struct ku_configs * cfgs);

void 
ep_init(void)
{
    int i;
    for(i = 0; i < MAX_FILTER_NUM; ++i)
      ep_cfgs.filters[i] = 
          kzalloc(MAX_FILTER_SZ * sizeof(char), GFP_KERNEL);
    ep_cfgs.filter_ct = 0;
    ep_cfgs.ref = 0;
    ep_cfgs.ku_cfgs.count = 0;
    printk("ep_init\n");
}

void
ep_exit(void)
{
    int i;
    for(i = 0; i < MAX_FILTER_NUM; ++i)
      kfree(ep_cfgs.filters[i]);
    ep_cfgs.filter_ct = 0;
    printk("ep_exit\n");
}

int 
ep_open(struct inode *node, struct file *fp)
{
    printk(KERN_INFO "ep open\n");
    ++ep_cfgs.ref;
    return 0;
}

int 
ep_release(struct inode *node, struct file *fp)
{
    int i;
    printk(KERN_INFO "ep release\n");

    //for(i = 0; i < MAX_FILTER_NUM; ++i)
    //  kfree(ep_cfgs.filters[i]);
    //ep_cfgs.filter_ct = 0;
    if(ep_cfgs.ref > 0) --ep_cfgs.ref;
    if(!ep_cfgs.ref)
    {
        for(i = 0; i < SCTP_MAX_ASSOC; ++i)
          ku_sctpops_list.list[i].old_sctp_ops = NULL;
        ep_recover();
    }
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

static void
show_proto_ops(const struct proto_ops * ops)
{
    printk(KERN_INFO "family            = %d\n", ops->family);
    printk(KERN_INFO "owner             = %p\n", ops->owner);
    printk(KERN_INFO "release           = %p\n", ops->release);
    printk(KERN_INFO "connect           = %p\n", ops->connect);
    printk(KERN_INFO "bind              = %p\n", ops->bind);
    printk(KERN_INFO "socketpair        = %p\n", ops->socketpair);
    printk(KERN_INFO "accept            = %p\n", ops->accept);
    printk(KERN_INFO "getname           = %p\n", ops->getname);
    printk(KERN_INFO "poll              = %p\n", ops->poll);
    printk(KERN_INFO "ioctl             = %p\n", ops->ioctl);
    printk(KERN_INFO "compat_ioctl      = %p\n", ops->compat_ioctl);
    //printk(KERN_INFO "gettstamp           = %p\n", ops->gettstamp);
    printk(KERN_INFO "listen            = %p\n", ops->listen);
    printk(KERN_INFO "shutdown          = %p\n", ops->shutdown);
    printk(KERN_INFO "setsockopt        = %p\n", ops->setsockopt);
    printk(KERN_INFO "getsockopt        = %p\n", ops->getsockopt);
    //printk(KERN_INFO "show_fdinfo     = %p\n", ops->show_fdinfo);
    printk(KERN_INFO "sendmsg           = %p\n", ops->sendmsg);
    printk(KERN_INFO "recvmsg           = %p\n", ops->recvmsg);
    printk(KERN_INFO "mmap              = %p\n", ops->mmap);
    printk(KERN_INFO "sendpage          = %p\n", ops->sendpage);
    printk(KERN_INFO "splice_read       = %p\n", ops->splice_read);
    printk(KERN_INFO "peek_len          = %p\n", ops->peek_len);
    printk(KERN_INFO "set_peek_off      = %p\n", ops->set_peek_off);
    //printk(KERN_INFO "read_sock           = %p\n", ops->read_sock);
    //printk(KERN_INFO "sendpage_locked = %p\n", ops->sendpage_locked);
    //printk(KERN_INFO "sendmsg_locked  = %p\n", ops->sendmsg_locked);
    //printk(KERN_INFO "set_rcvlowat        = %p\n", ops->set_rcvlowat);
}

ssize_t 
ep_write(struct file *fp, const char __user *buf, size_t size, loff_t * offset)
{
    int uncopied, err, ret;
    size_t len; 
    size_t tolen;
    struct socket *sock;
    struct sock *sk;
    struct msghdr outmsg;
    struct kvec iov;
    struct sockaddr_in to;
    //struct proto_ops *ops;
    task_info_t task_info;

    printk("ep_write : len = %ld\n", size);
    

    /** check*/
    print_configs(&ep_cfgs.ku_cfgs);
    if(ep_cfgs.ku_cfgs.count == 0)
    {
        printk(KERN_ERR " ku config not set\n");
        return -ENXIO;
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
    memset(&task_info, 0, sizeof(task_info));
    sock = find_sock_by_pid_fd(ep_cfgs.ku_cfgs.configs[ep_default_link].pid,
                ep_cfgs.ku_cfgs.configs[ep_default_link].fd, &err, &task_info);
    if(!sock)
    {
        printk(KERN_ALERT "find_sock_by_pid_fd failed : "
                    "pid=%d, fd=%d, err=%d\n", 
                    ep_cfgs.ku_cfgs.configs[ep_default_link].pid, 
                    ep_cfgs.ku_cfgs.configs[ep_default_link].fd, err);
        return -ENXIO;
    }
    //ep_v(&task_info);
    //return -ENXIO;
    sk = sock->sk;
    printk(KERN_INFO "found socket : type=%d, proto-name=%s, family=%d, flags=%ld\n", 
                sock->type, sk->__sk_common.skc_prot->name, sock->ops->family, sock->flags);


    if(sock->ops->family == AF_INET && sock->sk->sk_protocol == IPPROTO_SCTP)
    {
        //ops = &new_sctp_ops;
        printk(KERN_INFO "IPPROTO_SCTP\n");
        if(!origin_sctp_ops || true)
        {
            printk(KERN_INFO "SCTP OPS REPLACE\n");
            //ep_v(&task_info);
            ep_replace();
        }
        memset(&outmsg, 0, sizeof(outmsg));
        memset(&iov, 0, sizeof(iov));
        memset(&to, 0, sizeof(to));
        tolen = sizeof(to);

        to.sin_family = AF_INET;
        to.sin_addr.s_addr = 
            ep_cfgs.ku_cfgs.configs[ep_default_link].ip;
        to.sin_port = 
            ep_cfgs.ku_cfgs.configs[ep_default_link].port;

        outmsg.msg_name = (void *)&to;
        outmsg.msg_namelen = tolen;
        outmsg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

        iov.iov_base = (void *)write_buf;
        iov.iov_len = len;


        ret = kernel_sendmsg(sock, &outmsg, &iov, 1, iov.iov_len);
        printk(KERN_INFO "kernel_sendmsg: ret=%d, len=%ld\n", ret, iov.iov_len);
        ep_v(&task_info);
        if(ret < iov.iov_len)
        {
            printk(KERN_ALERT "kernel_sendmsg err : ret=%d, len=%ld\n",
                        ret, iov.iov_len);
        }
    }
    else if(sock->ops->family == AF_INET && sock->sk->sk_protocol == IPPROTO_UDP)
    {
        printk(KERN_INFO "IPPROTO_UPD\n");
        ret = kernel_sendmsg(sock, &outmsg, &iov, 1, iov.iov_len);
        ep_v(&task_info);
        ret = len;
    }
    else
    {
        ret = -EINVAL;
    }
    return ret;
}

long 
ep_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
    int uncopied, i;
    printk(KERN_INFO "ep ioctl\n");

    switch(cmd)
    {
        case IOCSPID:
            //ep_pid = arg;
            //printk(KERN_INFO "ep ioctl set pid : %d\n", ep_pid);
            break;
        case IOCGPID:
            //*(pid_t *)arg  = ep_pid;
            //printk(KERN_INFO "ep ioctl get pid : %d\n", ep_pid);
            break;
        case IOCSFD:
            //ep_fd = arg;
            //printk(KERN_INFO "ep ioctl set fd : %d\n", ep_fd);
            break;
        case IOCGFD:
            //*(int *)arg = ep_fd;
            //printk(KERN_INFO "ep ioctl get fd : %d\n", ep_fd);
            break;
        case IOCSIP:
            //ep_ip = arg;
            //printk(KERN_INFO "ep ioctl set ip : %08x\n", ep_ip);
            break;
        case IOCGIP:
            //*(uint32_t *)arg = ep_ip;
            //printk(KERN_INFO "ep ioctl get ip : %08x\n", ep_ip);
            break;
        case IOCSPORT:
            //ep_port = arg;
            //printk(KERN_INFO "ep ioctl set port : %04x\n", ep_port);
            break;
        case IOCGPORT:
            //*(uint16_t *)arg = ep_port;
            //printk(KERN_INFO "ep ioctl get port : %04x\n", ep_port);
            break;
        case IOCSONOFF:
            ep_work = arg;
            printk(KERN_INFO "ep ioctl set work : %d\n", ep_work);
            break;
        case IOCGONOFF:
            *(int*)arg = ep_work;
            printk(KERN_INFO "ep ioctl get work : %d\n", ep_work);
            break;
        case IOCSCONFIGS:
            //ep_cfgs.ku_cfgs = *(struct ku_configs *)arg;
            uncopied = copy_from_user(&ep_cfgs.ku_cfgs,
                        (struct ku_configs *)arg,
                        sizeof(struct ku_configs));
            if(uncopied)
            {
                printk(KERN_INFO "IOCSCONFIGS : copy_from_user failed\n");
                return -EINVAL;
            }
            else
            {
                printk(KERN_INFO "ep ioctl set config :\n");
                print_configs(&ep_cfgs.ku_cfgs);
            }
            break;
        case IOCGCONFIGS:
            *(struct ku_configs *)arg = ep_cfgs.ku_cfgs;
            printk(KERN_INFO "ep ioctl get config :\n");
            print_configs((struct ku_configs *)arg);
            break;
        case IOCADDFILTER:
            if(ep_cfgs.filter_ct == MAX_FILTER_NUM)
            {
                printk(KERN_ERR "too many filers\n");
                return -EINVAL;
            }
            uncopied = copy_from_user(ep_cfgs.filters[ep_cfgs.filter_ct++],
                        (char *)arg , strlen((char *)arg) + 1);
            if(uncopied)
            {
                printk(KERN_ERR "ep ioctl add filter : "
                            "copy_from_user failed : uncopied = %d\n", uncopied);
                return -EINVAL;
            }
            else
            {
                printk(KERN_INFO "ep ioctl add filter :\n");
                //ep_show_filter();
            }
            break;
        case IOCDELFILTER:
            if(ep_cfgs.filter_ct == 0)
              return -EINVAL;
            else
            {
                if(ep_del_filter((int)arg) == -1)
                  return -EINVAL;
                printk(KERN_INFO "ep ioctl del filter : ct= %d : \n", 
                            ep_cfgs.filter_ct);
                //ep_show_filter();
            }
            break;
        case IOCCLRFILTER:
            ep_cfgs.filter_ct = 0;
            printk(KERN_INFO "ep ioctl clear filters : %d\n", 
                        ep_cfgs.filter_ct);
            break;
        case IOCLSTFILTER:
            printk(KERN_INFO "ep ioctl list filters\n");
            for(i = 0; i < ep_cfgs.filter_ct; ++i)
            {
                uncopied = copy_to_user(((char **)arg)[i], 
                            ep_cfgs.filters[i], 
                            strlen(ep_cfgs.filters[i]) + 1);
                if(uncopied)
                {
                    printk(KERN_ERR "copy_to_user : failed");
                    return -EINVAL;
                }
            }
            ((char **)arg)[i] = NULL;
            break;
        default:
            printk(KERN_INFO "ep ioctl invalid cmd : %d\n", cmd);
            return -EINVAL;
    }
    return 0;
}


static struct socket *
find_sock_by_pid_fd(pid_t pid, int fd, int *err, task_info_t * task_info)
{
    struct task_struct * task;
    struct files_struct *files;
    struct file * file;
    struct socket * sock;

    task = get_task_by_pid(pid);//lock task
    if(!task)
    {
        printk(KERN_ALERT "get_task_by_pid faild, pid = %d\n", pid);
        goto failed;
    }
    task_info->task = task;
    //printk(KERN_INFO "task->on_cpu = %d\n", task->on_cpu);

    files = get_files_by_task(task);//lock files
    if(!files)
    {
        //task_unlock(task);
        printk(KERN_ALERT "get_files_by_task failed\b");
        //return NULL;
        goto failed;
    }
    task_info->files = files;

    file = get_file_by_files_fd(files, fd);//lock file
    if(!file)
    {
        //task_unlock(task);
        //files_unlock(files);
        printk(KERN_ALERT "get_file_by_file_fd failed\b");
        goto failed;
    }
    task_info->file = file;

    //goto failed;
    sock = sock_from_file(file, err);
    return sock;
failed:
    task_info->files = NULL;
    task_info->file = NULL;
    task_info->task = NULL;
    return NULL;
}

static struct task_struct * 
get_task_by_pid(int pid)
{
    struct task_struct * task;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task)
    {
        get_task_struct(task);
        //task_lock(task);
    }
    rcu_read_unlock();
    return task;
}

static struct files_struct* 
get_files_by_task(struct task_struct * task)
{
    return ep_get_files_struct(task);
}

static struct files_struct *
ep_get_files_struct(struct task_struct *task)
{
    struct files_struct *files;

    task_lock(task);
    files = task->files;
    if (files)
    {
        //atomic_inc(&files->count);
        //spin_lock(&files->file_lock);
    }
    task_unlock(task);

    return files;
}

static struct file * 
get_file_by_files_fd(struct files_struct * files, int fd)
{
    struct file *file;

    rcu_read_lock();
    file = fcheck_files(files, fd);
    if (file) {
        //printk(KERN_INFO "get_file_by_files_fd 1 : f_count = %ld\n", file->f_count.counter);
        /* File object ref couldn't be taken */
        if (file->f_mode & FMODE_PATH /*||
                                        !atomic_long_inc_not_zero(&file->f_count)*/)
          file = NULL;
        //else
        //{
        //  //spin_lock(&file->f_lock);
        //}
        //printk(KERN_INFO "get_file_by_files_fd 2 : f_count = %ld\n", file->f_count.counter);
    }
    rcu_read_unlock();

    return file;
}

static int 
ep_replace(void)
{
    struct socket * sock;
    int err, i;
    task_info_t task_info;

    for(i = 0; i < ep_cfgs.ku_cfgs.count; ++i)
    {
        sock = find_sock_by_pid_fd(ep_cfgs.ku_cfgs.configs[i].pid, 
                    ep_cfgs.ku_cfgs.configs[i].fd, &err, &task_info);
        if(!sock) return -1;
        else
        {
            if(sock->ops->family == AF_INET)
            {
                switch(sock->sk->sk_protocol)
                {
                    case IPPROTO_SCTP:
                        printk(KERN_INFO "replace SCTP\n");
                        if(!ku_sctpops_list.list[i].old_sctp_ops || true)
                        {
                            ku_sctpops_list.list[i].old_sctp_ops = sock->ops;
                            ku_sctpops_list.list[i].new_sctp_ops = *sock->ops;
                            ku_sctpops_list.list[i].new_sctp_ops.recvmsg = ku_sctp_recvmsg;
                            printk("new ops :\n");
                            show_proto_ops(&ku_sctpops_list.list[i].new_sctp_ops);
                            sock->ops = &ku_sctpops_list.list[i].new_sctp_ops;
                        }
                        if(!origin_sctp_ops || true)
                        {
                            origin_sctp_ops = sock->ops;
                            show_proto_ops(sock->ops);
                            show_proto_ops(origin_sctp_ops);
                        }

                        break;
                    case IPPROTO_UDP:
                        printk(KERN_INFO "replace UDP\n");
                        break;
                    default:
                        break;
                }
            }
            ep_v(&task_info);
        }
    }
    printk(KERN_INFO "ep_replace finished\n");
    return 0;
}

void ep_recover(void)
{
    struct socket * sock;
    int err, i;
    task_info_t task_info;

    for(i = 0; i < ep_cfgs.ku_cfgs.count; ++i)
    {
        sock = find_sock_by_pid_fd(ep_cfgs.ku_cfgs.configs[i].pid, 
                    ep_cfgs.ku_cfgs.configs[i].fd, &err, &task_info);
        if(!sock) return;
        else
        {
            if(sock->ops->family == AF_INET)
            {
                switch(sock->sk->sk_protocol)
                {
                    case IPPROTO_SCTP:
                        printk(KERN_INFO "recover sctp\n");
                        if(origin_sctp_ops)
                        {
                            sock->ops = origin_sctp_ops;
                            show_proto_ops(sock->ops);
                        }
                        ep_cfgs.ku_cfgs.count = 0;
                        origin_sctp_ops = NULL;
                        break;
                    case IPPROTO_UDP:
                        printk(KERN_INFO "recover udp\n");
                        break;
                    default:
                        break;
                }
            }
            ep_v(&task_info);
        }
    }
    printk(KERN_INFO "ep_recover finished\n");
}

static void 
ep_unlock(task_info_t * task_info)
{
    spin_unlock(&task_info->file->f_lock);
    spin_unlock(&task_info->files->file_lock);
    task_unlock(task_info->task);
}

static void close_files(struct files_struct * files)
{
    int i, j;
    struct fdtable *fdt;

    j = 0;

    /*
     * It is safe to dereference the fd table without RCU or
     * ->file_lock because this is the last reference to the
     * files structure.  But use RCU to shut RCU-lockdep up.
     */
    rcu_read_lock();
    fdt = files_fdtable(files);
    rcu_read_unlock();
    for (;;) {
        unsigned long set;
        i = j * BITS_PER_LONG;
        if (i >= fdt->max_fds)
          break;
        set = fdt->open_fds[j++];
        while (set) {
            if (set & 1) {
                struct file * file = xchg(&fdt->fd[i], NULL);
                if (file) {
                    filp_close(file, files);
                    cond_resched();
                }
            }
            i++;
            set >>= 1;
        }
    }
}

static void free_fdmem(void *ptr)
{
    is_vmalloc_addr(ptr) ? vfree(ptr) : kfree(ptr);
}

static void __free_fdtable(struct fdtable *fdt)
{
    free_fdmem(fdt->fd);
    free_fdmem(fdt->open_fds);
    kfree(fdt);
}

static void 
ep_put_files_struct(struct files_struct *files)
{
    struct fdtable *fdt;

    if (atomic_dec_and_test(&files->count)) {
        close_files(files);
        /* not really needed, since nobody can see us */
        rcu_read_lock();
        fdt = files_fdtable(files);
        rcu_read_unlock();
        /* free the arrays if they are not embedded */
        if (fdt != &files->fdtab)
          __free_fdtable(fdt);
        /** TODO: we needed kmem_cache_free*/
        //kmem_cache_free(files_cachep, files);
    }
}


static void 
ep_fput(struct task_struct * task, struct file * file)
{
    if (atomic_long_dec_and_test(&file->f_count)) {
        /** TODO: need to release if last reference*/
        //unsigned long flags;

        //ep_file_sb_list_del(file);
        //if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
        //  init_task_work(&file->f_u.fu_rcuhead, ____fput);
        //  if (!task_work_add(task, &file->f_u.fu_rcuhead, true))
        //    return;
        //}
        //spin_lock_irqsave(&delayed_fput_lock, flags);
        //list_add(&file->f_u.fu_list, &delayed_fput_list);
        //schedule_work(&delayed_fput_work);
        //spin_unlock_irqrestore(&delayed_fput_lock, flags);
    }
}

static void
ep_put_task_struct(struct task_struct * task)
{
    rcu_read_lock();
    if(task)
    {
        put_task_struct(task);
        //task_lock(task);
    }
    rcu_read_unlock();
}

static void
print_configs(const struct ku_configs * cfgs)
{
    int i;
    printk(KERN_INFO "count = %d : \n", cfgs->count);
    for(i = 0; i < cfgs->count && i < KU_MAX_CONFIG; ++i)
      printk(KERN_INFO "pid=%d, fd=%d, ip=%08x, port=%04x\n",
                  cfgs->configs[i].pid, 
                  cfgs->configs[i].fd, 
                  cfgs->configs[i].ip, 
                  cfgs->configs[i].port);
}


static int ep_del_filter(int index)
{
    int i;

    if(index < 0 || index >= ep_cfgs.filter_ct) 
    {
        printk("ep_del_filter : invalid filter index %d\n", 
                    index);
        return -1;
    }

    /** move*/
    for(i = index; i < ep_cfgs.filter_ct - 1; ++i)
      memcpy(ep_cfgs.filters[i], ep_cfgs.filters[i + 1], MAX_FILTER_SZ);
    ep_cfgs.filter_ct--;

    return 0;
}

static void ep_show_filter(void)
{
    int i;
    for(i = 0; i < ep_cfgs.filter_ct; ++i)
      printk(KERN_INFO "filter : %s\n", ep_cfgs.filters[i]);
}

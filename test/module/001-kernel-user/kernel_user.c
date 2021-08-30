/* simple kernel module: hello
 * Licensed under GPLv2 or later
 * */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/netdevice.h>

#define DEVNAME "kudev"

/** FUNCTIONS*/
static int ku_open(struct inode *node, struct file *fp);
static int ku_release(struct inode *node, struct file *fp);
static ssize_t ku_read(struct file *fp, char __user *buf, size_t size, loff_t * offset);
static ssize_t ku_write(struct file *fp, const char __user *buf, size_t size, loff_t * offset);
static long ku_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);

static struct cdev * kudev = NULL;
static struct file_operations ku_fops = 
{
	.owner = THIS_MODULE,
	.open = ku_open,
	.release = ku_release,
	.read = ku_read,
	.write = ku_write,
	.unlocked_ioctl = ku_ioctl,
};

static int minor					= 0;
static int major					= 0;
static int count					= 0;
static int fops_registered			= 0;
static int is_open					= 0;
struct file *g_file					= NULL;
static struct task_struct *g_task	= NULL;
static struct files_struct *g_sfile = NULL;
static struct socket * g_socket		= NULL;

static int __init 
ku_init(void)
{
	int ret;
	dev_t devnum;

	printk(KERN_INFO "ku init\n");
	
	kudev = cdev_alloc();
	if(!kudev)
	{
		printk(KERN_ERR "ku_init failed : cdev_alloc\n");
		return -ENOMEM;
	}

	cdev_init(kudev, &ku_fops);
	ret = alloc_chrdev_region(&devnum, minor, count, DEVNAME);
	if(ret != 0)
	{
		goto ERR_ALLOC;
	}
	major = MAJOR(devnum);

	ret = cdev_add(kudev, devnum, count);
	if(ret != 0)
	{
		goto ERR_ADD;
	}

	printk(KERN_INFO "ku_init success : %d %d", major, minor);
	fops_registered = 1;
	return 0;

ERR_ADD:
	unregister_chrdev_region(devnum, count);
ERR_ALLOC:
	cdev_del(kudev);
	printk(KERN_ERR "ku_init failed : alloc_chrdev_region\n");
	return ret;
}

static void __exit 
hello_exit(void)
{
	printk(KERN_INFO "Hello world exit.\n");
}


static int 
ku_open(struct inode *node, struct file *fp)
{
	printk(KERN_INFO "ku open\n");
	if(is_open)
	{
		printk(KERN_INFO "ku already open\n");
		return -EMFILE;
	}
	return 0;
}

static int 
ku_release(struct inode *node, struct file *fp)
{
	printk(KERN_INFO "ku release\n");
	return 0;
}

static ssize_t 
ku_read(struct file *fp, char __user *buf, size_t size, loff_t * offset)
{
	printk(KERN_INFO "ku read\n");
	return 0;
}

static ssize_t 
ku_write(struct file *fp, const char __user *buf, size_t size, loff_t * offset)
{
	printk(KERN_INFO "ku write\n");
	return 0;
}

static long 
ku_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	printk(KERN_INFO "ku ioctl\n");
	return 0;
}

module_init(ku_init);
module_exit(hello_exit);

MODULE_AUTHOR("TIMI");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A simple Hello World Module.");
MODULE_ALIAS("a simplest module.");

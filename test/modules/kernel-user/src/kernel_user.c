/* simple kernel module: hello
 * Licensed under GPLv2 or later
 * */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/netdevice.h>
#include "entry_points.h"

#define DEVNAME "kudev"

/** FUNCTIONS*/
static int create_devfiles(void);
static void destroy_devfiles(void);

static struct cdev * kudev = NULL;
static struct file_operations ku_fops = 
{
	.owner = THIS_MODULE,
	.open = ep_open,
	.release = ep_release,
	.read = ep_read,
	.write = ep_write,
	.unlocked_ioctl = ep_ioctl,
};

static int minor					    = 0;
static int major					    = 0;
static const int count				    = 1;
static int fops_registered			    = 0;
//static int is_open					= 0;
//struct file *g_file					= NULL;
//static struct task_struct *g_task	    = NULL;
//static struct files_struct *g_sfile   = NULL;
//static struct socket * g_socket		= NULL;
static struct class *cls                = NULL;
//static char read_buf[1204];

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
		cdev_del(kudev);
		printk(KERN_ERR "ku_init failed : alloc_chrdev_region\n");
		return ret;
	}
	major = MAJOR(devnum);

	ret = cdev_add(kudev, devnum, count);
	if(ret != 0)
	{
		unregister_chrdev_region(devnum, count);
		printk(KERN_ERR "ku_init failed : cdev_add\n");
		return ret;
	}

	printk(KERN_INFO "ku_init success : %d %d\n", major, minor);
	fops_registered = 1;
    ret = create_devfiles();
    if(ret == 0)
    {
        printk(KERN_INFO "create_devfiles success\n");
    }
	return ret;
}

static void __exit 
ku_exit(void)
{
    destroy_devfiles();
	printk(KERN_INFO "ku exit.\n");
	if(fops_registered)
	{
		unregister_chrdev_region(MKDEV(major, minor), count);
		cdev_del(kudev);
		fops_registered = 0;
	}
}

static int 
create_devfiles(void)
{
    int i, j;
    struct device *dev;

    /* 在/sys中导出设备类信息 */
    cls = class_create(THIS_MODULE, DEVNAME);
    if(cls == NULL)
    {
        printk(KERN_ERR "create_devfiles failed : class_create\n");
        return -1;
    }

    /* 在cls指向的类中创建一组(个)设备文件 */
    for(i = minor;  i < (minor + count); i++){
        dev = device_create(cls, 
                    NULL, 
                    MKDEV(major,i),
                    NULL,
                    "%s%d", 
                    DEVNAME,
                    i);
        if(dev == NULL)
        {
            printk(KERN_ERR "create_devfiles failed : device_create\n");
            for(j = minor; j < i; ++j)
            {
                device_destroy(cls, MKDEV(major,j));
            }
            class_destroy(cls);
            return -1;
        }
        printk(KERN_ERR "Dev %s%d has been created\n", DEVNAME, i);
    }  
    return 0;
}

static void 
destroy_devfiles(void)
{
    int i;
    if(cls == NULL) 
    {
        printk(KERN_INFO "destroy_devfiles : class is null\n");
        return;
    }
    /* 在cls指向的类中删除一组(个)设备文件 */
    for(i = minor; i<(minor+count); i++){
        device_destroy(cls, MKDEV(major,i));
    }

    /* 在/sys中删除设备类信息 */
    class_destroy(cls);             //一定要先卸载device再卸载class
    printk(KERN_INFO "destroy_devfiles success");
}

module_init(ku_init);
module_exit(ku_exit);

MODULE_AUTHOR("ZYJ");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A simple Dev Module.");
MODULE_ALIAS("KU Module");

/* simple kernel module: hello
 * Licensed under GPLv2 or later
 * */

#ifndef _ENTRY_POINTS_H
#define _ENTRY_POINTS_H
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/netdevice.h>
#include "ku_ioctl.h"

/** Functions For User*/
int ep_open(struct inode *node, struct file *fp);
int ep_release(struct inode *node, struct file *fp);
ssize_t ep_read(struct file *fp, char __user *buf, size_t size, loff_t * offset);
ssize_t ep_write(struct file *fp, const char __user *buf, size_t size, loff_t * offset);
long ep_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);
void ep_recover(void);
void ep_exit(void);
void ep_init(void);

#endif

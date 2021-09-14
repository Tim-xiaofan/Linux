/* simple kernel module: hello
 * Licensed under GPLv2 or later
 * */

#ifndef _KU_IOCTL_H
#define _KU_IOCTL_H
#include <linux/ioctl.h>

#define IOC_MAGIC 's'
#define IOCSPID     _IOW(IOC_MAGIC, 0, int)
#define IOCGPID     _IOR(IOC_MAGIC, 0, int)
#define IOCSFD      _IOW(IOC_MAGIC, 1, int)
#define IOCGFD      _IOR(IOC_MAGIC, 1, int)
#define IOCSIP      _IOW(IOC_MAGIC, 2, int)
#define IOCGIP      _IOR(IOC_MAGIC, 2, int)
#define IOCSPORT    _IOW(IOC_MAGIC, 3, int)
#define IOCGPORT    _IOR(IOC_MAGIC, 3, int)

#endif

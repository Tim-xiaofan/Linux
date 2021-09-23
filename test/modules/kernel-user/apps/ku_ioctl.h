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
#define IOCSONOFF   _IOW(IOC_MAGIC, 4, int)
#define IOCGONOFF   _IOR(IOC_MAGIC, 4, int)
#define IOCSCONFIGS _IOW(IOC_MAGIC, 5, int)
#define IOCGCONFIGS _IOR(IOC_MAGIC, 5, int)
#define IOCADDFILTER _IOW(IOC_MAGIC, 6, int)
#define IOCLSTFILTER _IOR(IOC_MAGIC, 6, int)
#define IOCDELFILTER _IOW(IOC_MAGIC, 7, int)
#define IOCCLRFILTER _IOW(IOC_MAGIC, 8, int)

#define KU_MAX_CONFIG 4
#define KU_ON   1
#define KU_OFF  0

struct ku_config
{
    pid_t pid;
    int fd;
    int ip;
    int port;
};

struct ku_configs
{
    int count;
    struct ku_config configs[KU_MAX_CONFIG];
};

#endif

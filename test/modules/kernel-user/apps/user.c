#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include "ku_ioctl.h"

#define BUF_SIZE    128
#define IP          "127.0.0.1"
#define PORT        7788

static char buf[256];
static bool force_quit          = false;
static const char * devfile     = NULL;
static int sockfd               = -1;
static int devfd                = -1;

static void 
signal_handle(int signum)
{
    if(signum == SIGINT)
    {
        printf("Preparing to quit...\n");
        force_quit = true;
    }
}

static int 
mod_config(void)
{
    pid_t pid;
    int ret, tmpdevfd;

    //设置pid
    pid = getpid();
    ret = ioctl(devfd, IOCSPID, pid);
    if(ret == -1)
    {
        perror("ioctl IOCSPID");
        return -1;
    }

    //读取pid
    ret = ioctl(devfd, IOCGPID, &pid);
    if(ret == -1)
    {
        perror("ioctl IOCGPID");
        return -1;
    }
    printf("read pid : %d\n", pid);

    //设置sockfd
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);//面向消息的UDP
    if(socket < 0)
    {
        perror("socket");
        return -1;
    }
    ret = ioctl(devfd, IOCSFD, sockfd);
    if(ret == -1)
    {
        perror("ioctl IOCFD");
        return -1;
    }

    //读取sockfd
    ret = ioctl(devfd, IOCGFD, &tmpdevfd);
    if(ret == -1)
    {
        perror("ioctl IOCGFD");
        return -1;
    }
    printf("read sockfd : %d\n", tmpdevfd);

    //设置IP
    uint32_t ip = inet_addr(IP);
    struct in_addr in;
    ret = ioctl(devfd, IOCSIP, ip);
    if(ret == -1)
    {
        perror("ioctl IOCSIP");
        return -1;
    }
    
    ret = ioctl(devfd, IOCGIP, &ip);
    if(ret == -1)
    {
        perror("ioctl IOCGIP");
        return -1;
    }
    in.s_addr = ip;
    printf("read ip : %s\n", inet_ntoa(in));
    //设置程序端口
    uint16_t port = htons(PORT); 
    ret = ioctl(devfd, IOCSPORT, port);
    if(ret == -1)
    {
        perror("ioctl IOCSPORT");
        return -1;
    }
    
    ret = ioctl(devfd, IOCGPORT, &port);
    if(ret == -1)
    {
        perror("ioctl IOCGPORT");
        return -1;
    }
    printf("read port : %u\n", ntohs(port));
    return 0;
}

int main(int ac, char *av[])
{
    int ret;
    time_t tm;

    if(ac < 2)
    {
        printf("Usage : ./program devfile\n");
        return -1;
    }

    signal(SIGINT, signal_handle);

    devfile = av[1];
    printf("devfile = %s\n", devfile);
    devfd = open(devfile, O_RDWR);
    if(devfd < 0)
    {
        perror("open");
        exit(errno);
    }

    //config mod
    if(mod_config() == -1)
    {
        fprintf(stderr, "mod_config failed\n");
        close(devfd);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while(!force_quit)
    {
        tm = time(NULL);
        sprintf(buf, "%s", ctime(&tm));
        ret = write(devfd, buf, strlen(buf) + 1);
        if(ret < 0){
            perror("write");
            break;
        }
        sleep(1);
    }

    ret = read(devfd, buf, 7);
    if(ret < 0){
        perror("read");
    }
    else
    {
        printf("data from kernel : %s\n",buf);
    }
    
    close(devfd);
    close(sockfd);
    printf("done.\n");
    return 0;
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "./msfw_q.h"
#include "../semaphore-communicate/sem_test.h"

#define SHM_KEY 2056
#define SHM_SIZE 1024
#define MUTEX 0
#define EMPTY 1
#define FULL 2

/*创建信号量集合，有三个信号量
	*第一个信号量（索引为0）为互斥信号量，各个进程互斥访问缓冲区,初值1
	*第二个信号量（索引为1）为同步信号量，指示空缓冲区的个数，制约生产者放产品,初值BUF_SIZE
	*第三个信号量（索引为2）为同步信号量，指示，制约消费者取产品,初值0*/
void init(int *shmid, int *semid)
{
    int key = SHM_KEY;
    int size = SHM_SIZE;
    *shmid = shmget(key, size, IPC_CREAT | 0770);
    if (*shmid == -1)
    {
        printf("shmget %s\n", strerror(errno));
        return;
    }
    printf("shmid = %d\n", *shmid);

    //创建3个信号量
    *semid = semget(SEM_KEY, 3, IPC_CREAT | 0700);
    unsigned short a[3] = {1, BUF_SIZE, 0};
    printf("semid = %d\n", *semid);

    //初始化信号量
    union semun args;
    args.array = a;
    int ret = semctl(*semid, 0, SETALL, args);
    //查看信号量
    if (ret == -1)
    {
        printf("init semctl %s\n", strerror(errno));
    }
    //sem_v(semid, 0);
    int i;
    for(i = 0; i < 3; i++)
        printf("sem%d's val = %d\n", i, semctl(*semid, i, GETVAL));
}

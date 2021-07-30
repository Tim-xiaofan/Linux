#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/shm.h>

int main(int ac, char *av[])
{
    int shmid, semid;
    msfw_q *shm_addr;
    int i, num;
    pid_t pid = getpid();
    char *e; 

	if(ac != 3)
	{
		fprintf(stderr, "Usage ：./customer shmid semid\n");
		exit(EXIT_FAILURE);
	}
	printf("av[0] = %s, av[1] = %s, av[2] = %s\n",av[0], av[1], av[2]);
	shmid = atoi(av[1]);
	semid = atoi(av[2]);
	printf("consumer : shmid = %d, semid = %d\n", shmid, semid);

    shm_addr = (msfw_q *)shmat(shmid, 0, 0); //挂载内存
    if (shm_addr == (void *)-1)
    {
        fprintf(stderr, "shmat %s", strerror(errno));
        exit(errno);
    }
    srand((unsigned)(pid + time(NULL)));
    for (i = 0; i < 26; i++)
    {
        num = get_rand_num();
        ///申请一个产品
        sem_p(semid, FULL);
        //申请缓冲区使用权
        sem_p(semid, MUTEX);
        //sleep 0~3s
        sleep(num);
        //取出字母
        q_dequeue(shm_addr, (void **)&e); //消费一个产品
        printf("Consumer-%d consumes a product(%s), q : ", pid, e);
		free(e);
        q_print(shm_addr, print);
        //归还缓冲区使用权
        sem_v(semid, MUTEX);
        //释放一个空的缓冲区
        sem_v(semid, EMPTY);
    }
}

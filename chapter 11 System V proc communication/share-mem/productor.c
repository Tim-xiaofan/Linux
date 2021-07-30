#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/shm.h>

int main(int ac, char *av[])
{
    int shmid, semid, i, num;
    pid_t pid = getpid();
    char* e;
	if(ac != 3)
	{
		printf("Usage : ./productor shmid semid\n");
		exit(EXIT_FAILURE);
	}
	printf("av[0] = %s, av[1] = %s, av[2] = %s\n",av[0], av[1], av[2]);
	shmid = atoi(av[1]);
	semid = atoi(av[2]);
	printf("productor : shmid = %d, semid = %d\n", shmid, semid);

    msfw_q *shm_addr;
    shm_addr = (msfw_q *)shmat(shmid, 0, 0); //挂载内存
    if (shm_addr == (void *)-1)
    {
        printf("shmat %s", strerror(errno));
        return -1;
    }   
	q_info(shm_addr);
    for(i = 0; i < 26; i++)
    {
        //sleep 0~3s
        num = get_rand_num();
		printf("productor : sleeping %d\n", num);
        sleep(num);
        //申请一个空缓冲区
		printf("productor p a EMPTY...\n");
		sem_p(semid, EMPTY);
		printf("productor got a EMPTY...\n");
		//申请缓冲区使用权
		printf("productor p the buffer...\n");
		sem_p(semid, MUTEX);
		printf("productor used the buffer\n");
		//放入一个字母
        char ch = 'a' + i;
        e = (char *)malloc(sizeof(char) * 2);
		sprintf(e, "%c", ch);
		printf("productor : e = %s\n", e);
        q_enqueue(shm_addr, e);
		printf("productor : after enqueue\n");
		printf("Productor-%d products %s, q : ", pid, e);
		q_print(shm_addr, print);
		//归还缓冲区使用权
		sem_v(semid, MUTEX);
		//释放一个产品
		sem_v(semid, FULL);
    }
    if(shmdt(shm_addr) == -1)
        printf("shmdt is failed.\n");
}

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>

#include "common.h"
#define WORK 1

static int shmid = -1;
static int semid = -1;
msfw_q * q = NULL;

/**
  创建信号量集合，有三个信号量
  第一个信号量（索引为0）为互斥信号量，各个进程互斥访问缓冲区,初值1
  第二个信号量（索引为1）为同步信号量，指示空缓冲区的个数，制约生产者放产品,初值BUF_SIZE
  第三个信号量（索引为2）为同步信号量，指示，制约消费者取产品,初值0
 */
static 
int init(void)
{
    key_t key;
    int i;
    union semun args;
    unsigned short a[3] = {1, SHM_SIZE, 0};

	key = ftok("./shm_test", (uint8_t)time(NULL));
	if(key == -1)
	{
		perror("ftok");
		return -1;
	}
	printf("key == %d\n", key);
    shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0770);
    if (shmid == -1)
    {
        printf("shmget %s\n", strerror(errno));
        return -1;
    }
    printf("shmid = %d\n", shmid);
	q = (msfw_q *)shmat(shmid, 0, 0);
	q_init(q, 12);
	if(q == (void *)-1)
	{
		shmctl(shmid, IPC_RMID, 0); //销毁
		perror("init's shmat");
		return -1;
	}
	q_info(q);
	if(shmdt((void *)q) == -1)
	{
		shmctl(shmid, IPC_RMID, 0); //销毁
		perror("init's shmdt");
		return -1;
	}

    //创建3个信号量
    semid = semget(SEM_KEY, 3, IPC_CREAT | 0700);
	if(semid == -1)
	{
		shmctl(shmid, IPC_RMID, 0); //销毁
		perror("semget");
		return -1;
	}
    printf("semid = %d\n", semid);

    //初始化信号量
    args.array = a;
    if ((semctl(semid, 0, SETALL, args)) == -1)
    {
		semctl(semid, IPC_RMID, 0);
		shmctl(shmid, IPC_RMID, 0); //销毁
        printf("init semctl %s\n", strerror(errno));
		return -1;
    }
    //查看信号量
    for(i = 0; i < 3; i++)
	{
		printf("sem%d's val = %d\n", i, semctl(semid, i, GETVAL));
	}
	return 0;
}

static void 
fin(void)
{
	semctl(semid, IPC_RMID, 0);
	shmctl(shmid, IPC_RMID, 0); //销毁
}

#ifdef TEST
static void
print_i(const void * i)
{
	printf("%d", *(int *)i);
}

static void 
q_test(void)
{
	int i, *pi;
	msfw_q * q = q_create(512);
	if(!q) return;
	printf("count = %d\n", q_get_count(q));
	for(i = 0; i < 512; ++i)
	{
		pi = (int *)malloc(sizeof(int));
		*pi = i;
		q_enqueue(q, pi);
	}
	printf("count = %d\n", q_get_count(q));
	q_print(q, print_i);
	for(i = 0; i < 122; ++i)
	{
		q_dequeue(q, (void **)&pi);
		printf("dequeue: %d\n", *pi);
		free(pi);
	}
	printf("after dequeue : \n");
	q_print(q, print_i);
	pi = (int *)malloc(sizeof(int));
	*pi = 1024;
	q_enqueue(q, pi);
	printf("after enqueue : \n");
	q_print(q, print_i);
	q_destroy(q);
}
#endif

int main(int argc, char *argv[])
{
	char *av[4];
    int pid, i;
    
	if(init() == -1)
	  exit(EXIT_FAILURE);
#ifdef TEST
	q_test();
#endif
#ifdef WORK
    //创建1个生产者
	av[1] = (char *)malloc(sizeof(char) * 32);
	av[2] = (char *)malloc(sizeof(char) * 32);
	if(!av[0] || !av[1] || !av[2])
	{
		perror("main : malloc");
		fin();
		exit(errno);
	}
	sprintf(av[1], "%d", shmid);
	sprintf(av[2], "%d", semid);
	av[3] = NULL; 
    for (i = 0; i < 1; i++)
    {
        pid = fork();
        if (pid == -1)
            printf("fork error\n");
		else if (pid == 0)
        {
			av[0] = "consumer";
            //printf("test\n");
            if (execv("./consumer", av) < 0)
            {
                printf("execv %s\n", strerror(errno));
                exit(-1);
            }
        }
    }
    //创建1个消费者
    if (pid > 0)
    {
        for (i = 0; i < 1; i++)
        {
            pid = fork();
            if (pid == -1)
                perror("fork");
			else if (pid == 0)
            {
				av[0] = "productor";
                //printf("test\n");
                if (execv("./productor", av) < 0)
                {
                    printf("execv %s\n", strerror(errno));
                    exit(-1);
                }
            }
        }
    }
    //主进程最后退出
    printf("before wait\n");
    while (wait(0) != -1);
    printf("after wait\n");
    semctl(semid, IPC_RMID, 0);
    shmctl(shmid, IPC_RMID, 0); //销毁
#endif
	return 0;
}

/*用于共享内存的数据结构*/
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include "common.h"

/*初始化队列*/
msfw_q * q_create(int cap)
{
	int i;
	msfw_q * q = (msfw_q *) malloc(sizeof(msfw_q));
	if(!q)
	{
		perror("malloc for q");
		return NULL;
	}
    q->front = q->rear = 0;
    q->is_full = false;
    q->is_empty = true;
	cap++;
	q->cap = cap;
	q->data  = (void **)malloc(cap * sizeof(void *));
	if(!q->data)
	{
		perror("malloc for q->data");
		free(q);
		return NULL;
	}
	for(i = 0; i < cap; ++i)
	{
		q->data[i] = NULL;
	}
	return q;
}

int q_init(msfw_q *q , int cap)
{
	int i;
    q->front = q->rear = 0;
    q->is_full = false;
    q->is_empty = true;
	cap++;
	q->cap = cap;
	q->data  = (void **)malloc(cap * sizeof(void *));
	if(!q->data)
	{
		perror("malloc for q->data");
		free(q);
		return -1;
	}
	for(i = 0; i < cap; ++i)
	{
		q->data[i] = NULL;
	}
	return 0;
}

/*返回队列元素个数*/
int q_get_count(const msfw_q *q)
{
    return (q->rear - q->front + q->cap) % q->cap;
}

/*队尾插入元素*/
bool q_enqueue(msfw_q *q, void *e)
{
	printf("enter q_enqueue\n");
    if ((q->rear + 1) % q->cap == q->front)
	{
		printf("leave q_enqueue\n");
		return false;
	}
	printf("q_enqueue 1\n");
    q->data[q->rear] = e;
	printf("q_enqueue 2\n");
    q->rear = (q->rear + 1) % q->cap;
	printf("leave q_enqueue\n");
    return true;
}

/*队头元素出列*/
bool q_dequeue(msfw_q *q, void **e)
{
    if (q->front == q->rear)
        return false;
    *e = q->data[q->front];
    q->front = (q->front + 1) % q->cap;
    return true;
}

/*输出队列*/
void q_print(const msfw_q *q, itemprint_t print)
{
    int i;
    printf("q_list, count = %d : ", q_get_count(q));
    if (q->front == q->rear)
    {
        printf("-");
        return;
    }
    for (i = q->front; i!= q->rear; i = (i + 1) % q->cap)
    {
        print(q->data[i]);
		printf(" ");
    }
    printf("\n");
}

void q_info(const msfw_q * q)
{
	printf("q=%p, front=%d, rear=%d, cap=%d\n",
				q, q->front, q->rear, q->cap);
}

/*断队列是否已满*/
bool q_is_full(msfw_q *q)
{
    if ((q->rear + 1) % q->cap == q->front)
	{
		return true;
	}
    return false;
}

bool q_is_empty(msfw_q *q)
{
    if (q->front == q->rear)
        return true;
    return false;
}

void q_destroy(msfw_q *q)
{
	int *pi;
	while(q_dequeue(q, (void **)&pi))
	  free(pi);
	free(q->data);
	free(q);
}

int get_rand_num(void)
{
    return rand() % 4; //0~3s
}

/*信号量的p操作*/
int sem_p(int semid, int semnum)
{
    struct sembuf op;
    op.sem_num = semnum;
    op.sem_op = -1;
    op.sem_flg = 0; //默认操作
    if (semop(semid, &op, 1) == -1)
    {
        printf("semop p in proc-%d %s\n", getpid(),strerror(errno));
        return -1;
    }
    return 0;
}

/*信号量的v操作*/
int sem_v(int semid, int semnum)
{
    struct sembuf op;
    op.sem_num = semnum;
    op.sem_op = 1;
    op.sem_flg = 0; //默认操作
    if (semop(semid, &op, 1) == -1)
    {
        printf("semop v in proc-%d %s\n",  getpid(), strerror(errno));
        return -1;
    }
    return 0;
}

void print(const void * i)
{
	printf("{%s} ", (char *)i);
}

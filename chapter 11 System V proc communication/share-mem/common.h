/*用于共享内存的数据结构*/
#ifndef _COMMON_H
#define _COMMON_H
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>


#define SHM_SIZE 1024
#define MUTEX 0
#define EMPTY 1
#define FULL 2


#define  SEM_KEY 2055

union semun
{

    int val; /* value for SETVAL */

    struct semid_ds *buf; /* buffer for IPC_STAT, IPC_SET */

    unsigned short *array; /* array for GETALL, SETALL */

    struct seminfo *__buf; /* buffer for IPC_INFO */
} ;

//const int sems_count 2;

/*信号量的p操作*/
int sem_p(int semid, int semnum);

/*信号量的v操作*/
int sem_v(int semid, int semnum);

typedef struct node_item
{
    char data;
} item;

typedef void (*itemcpy_t)(void *dst, const void *si);
typedef void (*itemprint_t)(const void *i);

/*环形缓冲区,循环队列*/
typedef struct node
{
    void **data;
    int front, rear, cap;
    bool is_full;
    bool is_empty;
} msfw_q;

msfw_q * q_create(int cap);
int q_init(msfw_q *q , int cap);
void q_destroy(msfw_q *q);
int q_get_count(const msfw_q *q);
bool q_enqueue(msfw_q *q, void *e);
bool q_dequeue(msfw_q *q, void **e);
void q_print(const msfw_q *q, itemprint_t print);
bool q_is_full(msfw_q *q);
bool q_is_empty(msfw_q *q);
void q_info(const msfw_q * q);
int get_rand_num(void);
void print(const void * i);
#endif

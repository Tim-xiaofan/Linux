#include "./init.h"
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    int shmid, semid;
    init(&shmid, &semid); //创建3个信号量

    msfw_q *shm_addr;
    shm_addr = (msfw_q *)shmat(shmid, 0, 0); //挂载内存
    init_q(shm_addr);

    printf("%d\n", shm_addr->front);

    semctl(semid, IPC_RMID, 0);
    shmctl(shmid, IPC_RMID, 0); //销

}
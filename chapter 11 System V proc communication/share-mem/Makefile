shm_test:shm_test.o common.o consumer productor
	gcc -g -Wall shm_test.o common.o -o shm_test
shm_test.o:shm_test.c
	gcc -g -Wall -c shm_test.c -o shm_test.o
common.o:common.c
	gcc -g -Wall -c common.c -o common.o
consumer:common.o consumer.o
	gcc -g -Wall common.o consumer.o -o consumer
consumer.o:consumer.c
	gcc -g -Wall -c consumer.c -o consumer.o
productor:common.o productor.o
	gcc -g -Wall common.o productor.o -o productor
productor.o:productor.c
	gcc -g -Wall -c productor.c -o productor.o
clean:
	rm -f *.o shm_test consumer productor

libmyrecvfrom.so:my_recvfrom.c
	gcc -Wall -fPIC -shared -o libmyrecvfrom.so my_recvfrom.c -ldl

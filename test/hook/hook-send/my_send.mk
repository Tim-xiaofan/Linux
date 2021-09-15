libmysend.so:my_send.c
	gcc -Wall -fPIC -shared -o libmysend.so my_send.c -ldl

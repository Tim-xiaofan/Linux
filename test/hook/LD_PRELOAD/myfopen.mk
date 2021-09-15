libmyopen.so:my_fopen.c
	gcc -Wall -fPIC -shared -o libmyfopen.so my_fopen.c -ldl

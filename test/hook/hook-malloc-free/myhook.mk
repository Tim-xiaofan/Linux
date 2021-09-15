libmyhook.so:my_hook.c
	gcc -fPIC -shared -o libmyhook.so my_hook.c -ldl

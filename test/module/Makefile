##此处表示编写在本机上使用的，交叉编译器进行交叉编译，此处也需要改变。
KVERS=/usr/src/kernels/3.10.0-1160.36.2.el7.x86_64/

obj-m += hello.o

#Specify flags for the module compilation
EXTRA_CFLAGS = -g -o0

build: kernel_modules

kernel_modules:
	make -C $(KVERS) M=$(PWD) modules

clean:
	make -C $(KVERS)  M=$(PWD) clean

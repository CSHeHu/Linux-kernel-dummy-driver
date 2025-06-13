KDIR := ~/dev/kernel/char-misc/
obj-m := dummy.o


all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

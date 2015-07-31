NAME=pcspkr

obj-m += $(NAME).o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -I$(INCLUDEDIR)

all:
	./bin2hex.pl $(BINDIR)/bd 1 > $(INCLUDEDIR)/piggy.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	mv $(NAME).ko $(BINDIR)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

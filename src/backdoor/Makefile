CC=gcc
CFLAGS=-Wextra -Wall -fno-builtin -g -D_DEBUG -m32
LDFLAGS=-lpcap -lpthread -lrt -lssl
OBJECTS=backdoor.o queue.o

all: bd

bd: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -I $(INCLUDEDIR) -o $(BINDIR)/bd main.c $(OBJECTS) $(COMMONDIR)/common.o $(COMMONDIR)/util.o $(COMMONDIR)/google.o $(COMMONDIR)/base64.o

.c.o:
	$(CC) -c $(CFLAGS) -I $(INCLUDEDIR) $<

clean:
	rm *.o -f
	rm $(BINDIR)/bd -f

tags:
	ctags *.c *.h --extra=+fq --sort=yes

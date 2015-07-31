CC=gcc
CFLAGS=-Wall -Wextra -DDEBUG -g -m32
LDFLAGS=-lssl

all: util.o

util.o:
	$(CC) -c $(CFLAGS) -I$(INCLUDEDIR) common.c
	$(CC) -c $(CFLAGS) -I$(INCLUDEDIR) util.c
	$(CC) -c $(CFLAGS) -I$(INCLUDEDIR) base64.c
	$(CC) -c $(CFLAGS) -I$(INCLUDEDIR) google.c

clean:
	rm *.o -f

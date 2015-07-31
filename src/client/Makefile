CC=gcc
CFLAGS=-Wall -Wextra -DDEBUG -g -m32
LDFLAGS=-lpthread -lpcap -lssl
OBJECTS=client.o

all: cli

cli: $(OBJECTS)
	$(CC) -m32 -g $(LDFLAGS) -I $(INCLUDEDIR) -o $(BINDIR)/cli main.c $(OBJECTS) $(COMMONDIR)/common.o $(COMMONDIR)/util.o $(COMMONDIR)/google.o $(COMMONDIR)/base64.o

.c.o:
	$(CC) -c $(CFLAGS) -I $(INCLUDEDIR) $<

clean:
	rm *.o
	rm $(BINDIR)/cli

CC = gcc
CFLAGS = -Wall -I../libmysyslog
LDFLAGS = -L../libmysyslog -lmysyslog

all: myRPC-client

myRPC-client: myRPC-client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

myRPC-client.o: myRPC-client.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o myRPC-client

deb:
	dpkg-buildpackage -us -uc

.PHONY: all clean deb

CC = gcc
CFLAGS = -Wall -I../libmysyslog
LDFLAGS = -L../libmysyslog -lmysyslog

all: myRPC-server

myRPC-server: myRPC-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

myRPC-server.o: myRPC-server.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o myRPC-server

deb:
	dpkg-buildpackage -us -uc

.PHONY: all clean deb

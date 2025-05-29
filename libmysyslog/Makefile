CC = gcc
CFLAGS = -Wall -fPIC
LDFLAGS = -shared

all: libmysyslog.so

libmysyslog.so: libmysyslog.o
	$(CC) $(LDFLAGS) -o $@ $^

libmysyslog.o: libmysyslog.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.so

install:
	cp libmysyslog.so /usr/local/lib/
	ldconfig

.PHONY: all clean install

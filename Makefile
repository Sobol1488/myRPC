all:
	$(MAKE) -C libmysyslog
	$(MAKE) -C client
	$(MAKE) -C server

clean:
	$(MAKE) -C libmysyslog clean
	$(MAKE) -C client clean
	$(MAKE) -C server clean

deb:
	$(MAKE) -C client deb
	$(MAKE) -C server deb

install:
	$(MAKE) -C libmysyslog install
	cp client/myRPC-client /usr/local/bin/
	cp server/myRPC-server /usr/local/bin/
	mkdir -p /etc/myRPC
	cp config/myRPC.conf /etc/myRPC/
	cp config/users.conf /etc/myRPC/

.PHONY: all clean deb install

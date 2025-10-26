
pwd = $(shell pwd)
top = $(pwd)/../..

.PHONY: all test clean realclean

all:
	./build -s

test:
	cd $(top) && go test -v
	./tests.sh

clean realclean:
	rm -rf $(top)/bin

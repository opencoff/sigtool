
pwd = $(shell pwd)

.PHONY: all test clean realclean

all:
	./build -s

test:
	go test ./sign

clean realclean:
	rm -rf bin

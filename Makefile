
pwd = $(shell pwd)

.PHONY: all test clean realclean

all:
	mkdir -p bin
	go build -o bin/sigtool .

test:
	go test ./sign

clean realclean:
	rm -f bin/sigtool

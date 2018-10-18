
pwd = $(shell pwd)
GOPATH := $(pwd)/vendor:$(pwd)
export GOPATH

all:
	mkdir -p bin
	go get -d .
	go build -o bin/sigtool .

test:
	go test sign
clean:
	rm -f bin/sigtool

realclean: clean
	rm -rf vendor

.PHONY: build

all: build

deps:
	go get -u github.com/golang/dep/...
	dep ensure -v

.pre:
	mkdir -p build

build: build-scepclient build-scepserver

build-scepclient: .pre
	cd cmd/scepclient && ./release.sh

build-scepserver: .pre
	cd cmd/scepserver && ./release.sh



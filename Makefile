.PHONY: build

export GO111MODULE=on

all: build

.pre:
	mkdir -p build

gomodcheck: 
	@go help mod > /dev/null || (@echo micromdm requires Go version 1.11 or higher && exit 1)

deps: gomodcheck
	@go mod download

test:
	go test -cover -race ./...

build: build-scepclient build-scepserver

build-scepclient: .pre
	cd cmd/scepclient && ./release.sh

build-scepserver: .pre
	cd cmd/scepserver && ./release.sh

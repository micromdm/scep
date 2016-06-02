#!/bin/bash

VERSION="0.1.0.0"
NAME=scep
OUTPUT=../../build

echo "Building $NAME version $VERSION"

mkdir -p ${OUTPUT}

build() {
  echo -n "=> $1-$2: "
  GOOS=$1 GOARCH=$2 go build -o ${OUTPUT}/$NAME-$1-$2 -ldflags "-X main.version=$VERSION -X main.gitHash=`git rev-parse HEAD`" ./*.go
  du -h ${OUTPUT}/${NAME}-$1-$2
}

build "darwin" "amd64"
build "linux" "amd64"

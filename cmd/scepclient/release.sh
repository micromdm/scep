#!/bin/bash

VERSION="0.3.0.0"
NAME=scepclient
OUTPUT=../../build

echo "Building $NAME version $VERSION"

mkdir -p ${OUTPUT}

build() {
  set -e
  echo -n "=> $1-$2: "
  GOOS=$1 GOARCH=$2 go build -o ${OUTPUT}/$NAME-$1-$2 -ldflags "-X main.version=$VERSION -X main.gitHash=`git rev-parse HEAD`" ./*.go
  du -h ${OUTPUT}/${NAME}-$1-$2
  set +e
}

build "darwin" "amd64"
build "linux" "amd64"

#!/bin/sh

set -xe

build(){
  mkdir -p "$OUTDIR"
  export OSTAG="$GOOS"
  if [ "$GOOS" = "darwin" ] ; then
    OSTAG="mac"
  fi
  export EXT=""
  if [ "$GOOS" = "windows" ] ; then
    EXT=".exe"
  fi
  go mod tidy
  go build -ldflags "-s -w" -o "$OUTDIR/gowebdav-$VERSION-$GOARCH-${OSTAG}${EXT}"
}

export OUTDIR="./build/release/"
export VERSION="v0.1"

GOARCH="amd64" GOOS="linux" build
GOARCH="amd64" GOOS="windows" build
GOARCH="amd64" GOOS="darwin" build

GOARCH="arm64" GOOS="linux" build
GOARCH="arm64" GOOS="darwin" build


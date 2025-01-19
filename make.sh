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
  go build -ldflags "-s -w" -o "$OUTDIR/$APP_TAG-$GOARCH-${OSTAG}${EXT}"
}

export OUTDIR="./build/release/"
export APP_TAG=$(cat main.go | sed -n 's/.*APP_TAG.*=.*"\([^"]*\)"/\1/p' | tail -n 1)

GOARCH="amd64" GOOS="linux" build
GOARCH="amd64" GOOS="windows" build
GOARCH="amd64" GOOS="darwin" build

GOARCH="arm64" GOOS="linux" build
GOARCH="arm64" GOOS="darwin" build


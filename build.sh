#!/bin/bash
set -euo pipefail

rm -rf bin
mkdir -p bin

if [ ! -f "main.go" ]; then
    echo "main.go not found."
    exit 1
fi

for os in linux darwin win32; do
    if [ "$os" = "win32" ]; then
        goos="windows"
    else
        goos=$os
    fi
    for arch in x64 arm64; do
        if [ "$arch" = "x64" ]; then
            goarch="amd64"
        else
            goarch=$arch
        fi
        if [ "$os" = "win32" ]; then
            ext=".exe"
        else
            ext=""
        fi
        mkdir -p bin/${os}-${arch}
        GOOS=$goos GOARCH=$goarch go build -o ./bin/${os}-${arch}/wispurr${ext} main.go
        chmod +x ./bin/${os}-${arch}/wispurr${ext}
    done
done

echo "Finished building binaries to ./bin/"

if [ ! -d "dist" ]; then
    echo "dist/ not found; run 'pnpm run compile' first." >&2
    exit 1
fi

cp package.json README.md LICENSE dist/
cp example.config.json dist/config.json

echo "Finished copying package files to ./dist/"

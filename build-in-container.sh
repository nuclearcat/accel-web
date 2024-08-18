#!/bin/bash
sudo docker run --rm -v $(pwd):/app -w /app -e GOOS=linux -e GOARCH=amd64 golang:latest go build -v -o app
if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi

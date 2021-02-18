#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <client> <server>"
    echo
    echo "where <client> and <server> are one of the following:"
    echo "boringssl, cloudflare-go, nss, rustls"
    exit 1
fi

env SERVER_SRC=./impl-endpoints SERVER=$2 \
    CLIENT_SRC=./impl-endpoints CLIENT=$1 \
    docker-compose build

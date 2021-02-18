#!/bin/bash

# After typing Ctrl-C, Docker waits this number of seconds to interrupt the
# containers.
TIMEOUT=0

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <client> <server> <testcase>"
    echo
    echo "where <client> and <server> are one of the following:"
    echo "boringssl, cloudflare-go, nss, rustls"
    echo
    echo "and <testcase> is one of the following:"
    echo "dc, ech-accept, ech-reject"
    exit 1
fi

env SERVER_SRC=./impl-endpoints SERVER=$2 \
    CLIENT_SRC=./impl-endpoints CLIENT=$1 \
    TESTCASE=$3 \
    docker-compose up --timeout $TIMEOUT

docker-compose stop

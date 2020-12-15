#!/bin/sh
set -e

if [ "$ROLE" == "client" ]; then
    # TODO
    true
else
    echo "Running BoringSSL server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    bssl server -accept 4433 -cert /root.pem -key /key.pem
fi

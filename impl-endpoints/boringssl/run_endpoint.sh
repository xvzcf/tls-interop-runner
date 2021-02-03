#!/bin/sh
set -e

sh /setup-routes.sh

if [ "$ROLE" = "client" ]; then
    # TODO
    true
else
    echo "Running BoringSSL server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    bssl server -accept 4433 -cert /testdata/example.crt -key /testdata/example.key -subcert /testdata/dc.txt
fi

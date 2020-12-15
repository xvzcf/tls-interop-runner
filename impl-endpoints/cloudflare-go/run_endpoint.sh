#!/bin/sh
set -e

ROLE=client

if [ "$ROLE" = "client" ]; then
    # TODO
    echo "Running Cloudflare-Go client."
    echo "Client params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    /cf-go/bin/go run /client.go
else
    true
    # TODO
fi

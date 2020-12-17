#!/bin/sh
set -e

ROLE=client

if [ "$ROLE" = "client" ]; then
    # TODO
    echo "Running Cloudflare-Go client."
    echo "Client params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    /cf-go/bin/go run /runner.go -role=client -test=${TESTCASE}
else
    true
    # TODO
fi

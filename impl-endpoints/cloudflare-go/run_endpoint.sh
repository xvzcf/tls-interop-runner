#!/bin/sh
set -e

if [ "$ROLE" = "client" ]; then
    echo "Running Cloudflare-Go client."
    echo "Client params: $CLIENT_PARAMS"
    echo "Test case: $TESTCASE"
    runner -role=client -test=${TESTCASE}
else
    echo "Running Cloudflare-Go server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    runner -role=server -test=${TESTCASE}
fi

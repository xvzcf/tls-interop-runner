#!/bin/sh
set -e

echo "Using commit:" "$(cat commit.txt)"

if [ "$ROLE" = "client" ]; then
    # TODO
    true
else
    echo "Running rustls server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    tlsserver --certs /testdata/server.cert --key /testdata/server.key -p 4433 echo
fi

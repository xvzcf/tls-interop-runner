#!/bin/sh
set -e

echo "Using commit:" `cat commit.txt`

if [ "$ROLE" == "client" ]; then
    # TODO
    true
else
    echo "Running BoringSSL server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    tlsserver --certs /end.fullchain --key /end.key -p 4433 echo
fi

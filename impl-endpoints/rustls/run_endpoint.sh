#!/bin/sh
set -e

/setup.sh

echo "Using commit:" "$(cat commit.txt)"

if [ "$ROLE" = "client" ]; then
    # TODO
    true
else
    echo "Running rustls server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    tlsserver --certs /certs/server.cert --key /certs/server.key -p 4433 echo
fi

#!/bin/sh

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

set -e

sh /setup-routes.sh

echo "Using commit:" "$(cat commit.txt)"

if [ "$ROLE" = "client" ]; then
    # TODO
    true
else
    echo "Running rustls server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    tlsserver --certs /test-inputs/example.crt --key /test-inputs/example.key -p 4433 echo
fi

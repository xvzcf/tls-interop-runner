#!/bin/sh

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

set -e

sh /setup-routes.sh

if [ "$ROLE" = "client" ]; then
    runner -as-client -testcase dc
else
    echo "Running BoringSSL server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    bssl server -loop -accept 4433 -cert /test-inputs/example.crt -key /test-inputs/example.key -subcert /test-inputs/dc.txt
fi

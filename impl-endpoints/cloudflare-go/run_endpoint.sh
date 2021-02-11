#!/bin/sh

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

set -e

sh /setup-routes.sh

if [ "$ROLE" = "client" ]; then
    echo "Running Cloudflare-Go client."
    echo "Test case: $TESTCASE"
    runner -role=client -test=${TESTCASE}
else
    echo "Running Cloudflare-Go server."
    echo "Test case: $TESTCASE"
    runner -role=server -test=${TESTCASE}
fi

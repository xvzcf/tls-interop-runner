#!/bin/sh

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

set -e

sh /setup-routes.sh

if [ "$TESTCASE" != "ech-accept" ]; then
    echo "Testcase not supported."
    exit 64
fi

python3 /ech-key-converter.py

if [ "$ROLE" = "client" ]; then
    env LD_LIBRARY_PATH=/wolfssl/lib /client-ech
else
    echo "Role not supported."
    exit 64
fi

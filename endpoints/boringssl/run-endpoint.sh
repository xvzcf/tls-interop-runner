#!/bin/sh

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

set -e

sh /setup-routes.sh

if [ "$TESTCASE" = "ech-accept" ]; then
    python3 /ech-key-converter.py
fi

if [ "$ROLE" = "client" ]; then
    /runner -as-client -testcase "${TESTCASE}"
else
    /runner -testcase "${TESTCASE}"
fi

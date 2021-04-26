#!/bin/sh

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

set -e

sh /setup-routes.sh

if [ "$ROLE" = "client" ]; then
    runner -as-client -testcase "${TESTCASE}"
else
    runner -testcase "${TESTCASE}"
fi

# SPDX-FileCopyrightText: 2023 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

WOLFSSL_DIR = /wolfssl
CFLAGS = -Wall -Werror -I${WOLFSSL_DIR}/include
LDFLAGS = -L${WOLFSSL_DIR}/lib -lwolfssl

client-ech: client-ech.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

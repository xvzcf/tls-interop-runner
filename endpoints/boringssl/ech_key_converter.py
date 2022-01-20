#!/usr/bin/python3

# SPDX-FileCopyrightText: 2022 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

"""
This script takes an ECHKey and outputs the base64-formatted key in a file
called |ech_key_only|, and the corresponding configuration in a file called
|ech_config|, with the length prefixes stripped.
"""

import struct
import base64

with open("/test-inputs/ech_key", "rb") as f:
    ech_key_raw = base64.b64decode(f.read(), None, True)
    offset = 2

    # Parse out the private key.
    private_key_length = struct.unpack("!H", ech_key_raw[:offset])[0]
    private_key = ech_key_raw[offset : offset + private_key_length]
    offset += private_key_length

    # Parse out the config.
    config_length = struct.unpack("!H", ech_key_raw[offset:offset + 2])[0]
    offset += 2
    config = ech_key_raw[offset : offset + config_length]

    out = open("/ech_key_only", "wb")
    out.write(base64.b64encode(bytearray(private_key)))
    out.close()

    out = open("/ech_config", "wb")
    out.write(base64.b64encode(bytearray(config)))
    out.close()

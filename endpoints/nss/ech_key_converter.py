#!/usr/bin/python3

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

"""
This script rewrites an ECHKey to contain a PKCS8-formatted keypair, which is the format
required by the selfserv utility in NSS. Specifically, the output is formed as follows:

    *  struct {
    *     opaque pkcs8_ech_keypair<0..2^16-1>;
    *     ECHConfigList configs<0..2^16>; // draft-ietf-tls-esni-09
    * } ECHKey;
"""

import sys
import struct
import base64

ECH_VERSION = 0xFE0D
DHKEM_X25519_SHA256 = 0x0020

# Hardcoded ASN.1 for ECPrivateKey, curve25519. See section 2 of rfc5958.
pkcs8_start = b"\x30\x67\x02\x01\x00\x30\x14\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01\x04\x4C\x30\x4A\x02\x01\x01\x04\x20"
pkcs8_pub_header = b"\xa1\x23\x03\x21\x00"


def convert_ech_key(in_file, out_file):
    with open(in_file, "rb") as f:
        ech_keypair = base64.b64decode(f.read(), None, True)

        offset = 0

        # Parse the private key.
        length = struct.unpack("!H", ech_keypair[:2])[0]
        offset += 2
        private_key = ech_keypair[offset : offset + length]
        offset += length

        # Encode the ECHConfigList that will be output.
        ech_config_list = ech_keypair[offset:]

        # Parse the length of the ECHConfigList.
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        # Parse ECHConfig.version, where ECHConfig is the first configuration in
        # ECHConfigList.
        version = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        # Verify that the version number is as expected.
        if version != ECH_VERSION:
            print("ECHConfig.version is not {}: got {}".format(ECH_VERSION, hex(version)))
            exit(1)

        # Parse ECHConfig.Length, which indicates the length of
        # ECHConfig.contents.
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        # Parse ECHConfig.contents.key_config.config_id.
        config_id = struct.unpack("!B", ech_keypair[offset : offset + 1])[0]
        offset += 1

        # Parse ECHConfig.contents.key_config.kem_id.
        kem_id = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        # Verify that the KEM is X25519. We don't support anything else.
        kem_id = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        if kem_id != DHKEM_X25519_SHA256:
            print("Unsupported KEM ID: %x", hex(kem_id))
            exit(1)

        # Parse ECHConfig.contents.key_config.public_key.
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        public_key = ech_keypair[offset : offset + length]
        offset += length

        pkcs8 = bytearray()
        pkcs8 += (
            bytearray(pkcs8_start)
            + bytearray(private_key)
            + bytearray(pkcs8_pub_header)
            + bytearray(public_key)
        )

        out_bytes = bytearray()
        out_bytes += struct.pack("!H", len(pkcs8)) + pkcs8 + ech_config_list

        out = open(out_file, "wb")
        out.write(base64.b64encode(out_bytes))
        out.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ech_key_converter.py <in_ech_keypair> <out_pkcs8>")
        exit(1)

    convert_ech_key(sys.argv[1], sys.argv[2])

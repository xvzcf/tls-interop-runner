#!/usr/bin/python3

"""
This script rewrites an ECHKey to contain a PKCS8-formatted keypair, which is the format
required by the selfserv utility in NSS. Specifically, the output is formed as follows:

    *  struct {
    *     opaque pkcs8_ech_keypair<0..2^16-1>;
    *     ECHConfigs configs<0..2^16>; // draft-ietf-tls-esni-09
    * } ECHKey;
"""

import sys
import struct
import base64

ECH_VERSION = 0xFE09
DHKEM_X25519_SHA256 = 0x0020

# Hardcoded ASN.1 for ECPrivateKey, curve25519. See section 2 of rfc5958.
pkcs8_start = b"\x30\x67\x02\x01\x00\x30\x14\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01\x04\x4C\x30\x4A\x02\x01\x01\x04\x20"
pkcs8_pub_header = b"\xa1\x23\x03\x21\x00"


def convert_ech_key(in_file, out_file):
    with open(in_file, "rb") as f:
        ech_keypair = base64.b64decode(f.read(), None, True)

        offset = 0
        length = struct.unpack("!H", ech_keypair[:2])[0]
        offset += 2
        private_key = ech_keypair[offset : offset + length]
        offset += length

        ech_configs = ech_keypair[offset:]

        # Parse the public key out of the ECHConfig.
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        version = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        if version != ECH_VERSION:
            print("ECHConfig.version is not 0xFE09: %x", hex(version))
            exit(1)

        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        # Public name
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2 + length

        # Public key
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        public_key = ech_keypair[offset : offset + length]
        offset += length

        # Verify that the KEM is X25519. We don't support anything else.
        kem_id = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        if kem_id != DHKEM_X25519_SHA256:
            print("Unsupported KEM ID: %x", hex(kem_id))
            exit(1)

        pkcs8 = bytearray()
        pkcs8 += (
            bytearray(pkcs8_start)
            + bytearray(private_key)
            + bytearray(pkcs8_pub_header)
            + bytearray(public_key)
        )

        out_bytes = bytearray()
        out_bytes += struct.pack("!H", len(pkcs8)) + pkcs8 + ech_configs

        out = open(out_file, "wb")
        out.write(base64.b64encode(out_bytes))
        out.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ech_key_converter.py <in_ech_keypair> <out_pkcs8>")
        exit(1)

    convert_ech_key(sys.argv[1], sys.argv[2])

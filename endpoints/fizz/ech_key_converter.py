#!/usr/bin/python3

"""
This script converts the generated ECHKey struct (shown below) into the key format and
JSON config format expected by the fizz tool.
 struct {
     opaque sk<0..2^16-1>;
     ECHConfig config<0..2^16>; // draft-ietf-tls-esni-09
 } ECHKey;
"""

import sys
import struct
import base64
import json

ECH_VERSION = 0xFE0D
# KEM IDs
DHKEM_P256_SHA256 = 0x0010
DHKEM_P384_SHA384 = 0x0011
DHKEM_P521_SHA512 = 0x0012
DHKEM_X25519_SHA256 = 0x0020

# KDF IDs
KDF_SHA256 = 0x0001
KDF_SHA384 = 0x0002
KDF_SHA512 = 0x0003

# AEAD IDs
AEAD_AES_128 = 0x0001
AEAD_AES_256 = 0x0002
AEAD_CHACHA20_POLY1305 = 0x0003

def kemtostr(kem_id):
    if kem_id == DHKEM_P256_SHA256:
        return "secp256r1"
    elif kem_id == DHKEM_P384_SHA384:
        return "secp384r1"
    elif kem_id == DHKEM_P521_SHA512:
        return "secp521r1"
    elif kem_id == DHKEM_X25519_SHA256:
        return "x25519"
    else:
        print("unsupported KEM id: %x", kem_id)
        exit(1)

def kdftostr(kdf_id):
    if kdf_id == KDF_SHA256:
        return "Sha256"
    elif kdf_id == KDF_SHA384:
        return "Sha384"
    elif kdf_id == KDF_SHA512:
        return "Sha512"
    else:
        print("unsupported KDF id: $x", kdf_id)
        exit(1)

def aeadtostr(aead_id):
    if aead_id == AEAD_AES_128:
        return "TLS_AES_128_GCM_SHA256"
    elif aead_id == AEAD_AES_256:
        return "TLS_AES_256_GCM_SHA384"
    elif aead_id == AEAD_CHACHA20_POLY1305:
        return "TLS_CHACHA20_POLY1305_SHA256"
    else:
        print("unsupported AEAD id: %x", aead_id)
        exit(1)

#TODO update this func to comply with ech15 (currently ech09)
def convert_ech_key(in_file, out_key, out_config):
    with open(in_file, "rb") as f:
        ech_keypair = base64.b64decode(f.read(), None, True)
        print(ech_keypair)

        offset = 0
        if out_key != "-n":    
            length = struct.unpack("!H", ech_keypair[:2])[0]
            offset += 2
            private_key = ech_keypair[offset : offset + length]
            offset += length

        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        version = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        print("private:", private_key)
        print("version:", hex(version))

        if version != ECH_VERSION:
            print("ECHConfig.version is not 0xFE0D: %x", hex(version))
            exit(1)

        # These are all ECHConfigContents
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2

        # ECHConfig ID
        config_id = ech_keypair[offset : offset + 1]
        offset += 1
        print("Config id:", int.from_bytes(config_id, "big"))

        # KEM
        kem_id = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        print("KEM id:", hex(kem_id))

        # Public key
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        public_key = ech_keypair[offset : offset + length]
        offset += length

        # KDF and AEAD ID
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        cipher_suites = []
        cipher_offset = 0
        while cipher_offset < length:
            kdf_id = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
            print("kdf_id:", kdf_id)
            offset += 2
            cipher_offset += 2
            aead_id = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
            print("aead_id:", aead_id)
            offset += 2
            cipher_offset += 2
            cipher_suites.append({"kdf_id": kdftostr(kdf_id), "aead_id": aeadtostr(aead_id)})

        if cipher_offset != length:
            print("cipher suite size mismatch: %d != %d", cipher_offset, length)
            exit(1)

        # Max name len
        max_name_length = ech_keypair[offset : offset + 1]
        offset += 1
        print("Max name len:", int.from_bytes(max_name_length, "big"))

        length = struct.unpack("!H", b'\x00' + ech_keypair[offset : offset + 1])[0]
        offset += 1
        public_name = ech_keypair[offset : offset + length]
        print("offset:", offset, "length:", length, "offset+len:", offset+length)
        offset += length
        print("public name:", public_name)

        # Extensions
        print("ech_keypair len:", len(ech_keypair))
        print("offset:", offset)
        length = struct.unpack("!H", ech_keypair[offset : offset + 2])[0]
        offset += 2
        extensions = ech_keypair[offset : offset + length]
        offset += length

        if out_key != "-n":    
            out_key_file = open(out_key, "w")
            out_key_file.write(private_key.hex() + "\n")
            out_key_file.write(public_key.hex() + "\n")
            out_key_file.close()

        # TODO Update this json format to comply with fizz's version
        # FIZZ is still unable to parse this. Look into this >:L
        ech_json = {
            "echconfigs": [{
                "version": "Draft15",
                "public_name": public_name.decode("utf-8"),
                "public_key": public_key.hex(),
                "kem_id": kemtostr(kem_id),
                "cipher_suites": cipher_suites,
                "maximum_name_length": max_name_length.hex(),
                "extensions": extensions.hex(),
                "config_id": config_id.hex()
            }]
        }
        out_config_file = open(out_config, "w")
        json.dump(ech_json, out_config_file)
        out_config_file.close()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: ech_key_converter.py <in_ech_keypair> [<out_echkey>||-n] <out_config>")
        print("       -n will skip parsing the key and only parse config");
        exit(1)

    convert_ech_key(sys.argv[1], sys.argv[2], sys.argv[3])

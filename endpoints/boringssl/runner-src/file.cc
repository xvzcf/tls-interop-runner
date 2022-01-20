// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#include <stdio.h>
#include <iostream>

#include <openssl/base64.h>

#include <algorithm>
#include <vector>

#include "internal.h"

bool ReadAll(std::vector<uint8_t> *out, FILE *file) {
  out->clear();

  constexpr size_t kMaxSize = 1024 * 1024;
  size_t len = 0;
  out->resize(128);

  for (;;) {
    len += fread(out->data() + len, 1, out->size() - len, file);

    if (feof(file)) {
      out->resize(len);
      return true;
    }
    if (ferror(file)) {
      return false;
    }

    if (len == out->size()) {
      if (out->size() == kMaxSize) {
        fprintf(stderr, "Input too large.\n");
        return false;
      }
      size_t cap = std::min(out->size() * 2, kMaxSize);
      out->resize(cap);
    }
  }
}

bool DecodeBase64(std::vector<uint8_t> *out, const std::vector<uint8_t> *in) {
  size_t len;
  if (!EVP_DecodedLength(&len, in->size())) {
    fprintf(stderr, "EVP_DecodedLength failed\n");
    return false;
  }

  out->resize(len);
  if (!EVP_DecodeBase64(out->data(), &len, len, in->data(), in->size())) {
    fprintf(stderr, "EVP_DecodeBase64 failed\n");
    return false;
  }
  out->resize(len);
  return true;
}

static bool FromHexDigit(uint8_t *out, char c) {
  if ('0' <= c && c <= '9') {
    *out = c - '0';
    return true;
  }
  if ('a' <= c && c <= 'f') {
    *out = c - 'a' + 10;
    return true;
  }
  if ('A' <= c && c <= 'F') {
    *out = c - 'A' + 10;
    return true;
  }
  return false;
}
static bool HexDecode(std::string *out, const std::string &in) {
  if ((in.size() & 1) != 0) {
    return false;
  }

  std::unique_ptr<uint8_t[]> buf(new uint8_t[in.size() / 2]);
  for (size_t i = 0; i < in.size() / 2; i++) {
    uint8_t high, low;
    if (!FromHexDigit(&high, in[i * 2]) || !FromHexDigit(&low, in[i * 2 + 1])) {
      return false;
    }
    buf[i] = (high << 4) | low;
  }

  out->assign(reinterpret_cast<const char *>(buf.get()), in.size() / 2);
  return true;
}
bool ReadDelegatedCredential(std::vector<uint8_t> *dc_out,
                             std::vector<uint8_t> *priv_out,
                             const char *filename) {
  ScopedFILE f(fopen(filename, "rb"));
  std::vector<uint8_t> data;
  if (f == nullptr || !ReadAll(&data, f.get())) {
    fprintf(stderr, "Error reading %s.\n", filename);
    return false;
  }

  if (!data.empty()) {
    std::string dc_str = std::string(data.begin(), data.end());
    std::string::size_type comma = dc_str.find(',');
    if (comma == std::string::npos) {
      fprintf(stderr,
              "failed to find comma in delegated credential argument.\n");
      return false;
    }

    const std::string dc_hex = dc_str.substr(0, comma);
    const std::string pkcs8_hex = dc_str.substr(comma + 1);
    std::string dc, pkcs8;
    if (!HexDecode(&dc, dc_hex) || !HexDecode(&pkcs8, pkcs8_hex)) {
      fprintf(stderr, "failed to hex decode delegated credential.\n");
      return false;
    }
    dc_out->assign(dc.begin(), dc.end());
    priv_out->assign(pkcs8.begin(), pkcs8.end());

    return true;
  }
  return false;
}

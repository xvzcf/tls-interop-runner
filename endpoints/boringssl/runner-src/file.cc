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

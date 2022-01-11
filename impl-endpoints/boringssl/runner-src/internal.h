// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#ifndef BORINGSSL_RUNNER_INTERNAL_H
#define BORINGSSL_RUNNER_INTERNAL_H

#include <openssl/base.h>

#include <string>
#include <utility>
#include <vector>

#include <map>

struct FileCloser {
  void operator()(FILE *file) { fclose(file); }
};
using ScopedFILE = std::unique_ptr<FILE, FileCloser>;

enum ArgumentType {
  kRequiredArgument,
  kOptionalArgument,
  kBooleanArgument,
};
struct argument {
  const char *name;
  ArgumentType type;
  const char *description;
};
bool ParseKeyValueArguments(std::map<std::string, std::string> *out_args,
                            const std::vector<std::string> &args,
                            const struct argument *templates);

bool ReadAll(std::vector<uint8_t> *out, FILE *in);
bool DecodeBase64(std::vector<uint8_t> *out, const std::vector<uint8_t> *in);

unsigned int DoClient(std::string testcase);
unsigned int DoServer(std::string testcase);

#endif  // !BORINGSSL_RUNNER_INTERNAL_H

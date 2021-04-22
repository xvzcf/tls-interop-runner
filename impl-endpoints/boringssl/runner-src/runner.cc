// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <libgen.h>

#include "internal.h"

static const struct argument kArguments[] = {
    {
        "-testcase",
        kRequiredArgument,
        "Handle the tls-interop-runner delegated credentials testcase.",
    },
    {"-as-client", kBooleanArgument,
     "Handle testcases as a client. By default the testcases are handled "
     "from a server perspective."},
    {
        "",
        kOptionalArgument,
        "",
    },
};

int main(int argc, char **argv) {
  CRYPTO_library_init();

  int starting_arg = 1;
  std::vector<std::string> args;
  for (int i = starting_arg; i < argc; i++) {
    args.push_back(argv[i]);
  }

  std::map<std::string, std::string> args_map;
  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    return 1;
  }

  if (args_map.count("-as-client") != 0) {
    return DoClient(args_map["-testcase"]);
  }

  return DoServer(args_map["-testcase"]);
}

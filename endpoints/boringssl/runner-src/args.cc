// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#include <string>
#include <vector>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

bool ParseKeyValueArguments(std::map<std::string, std::string> *out_args,
                            const std::vector<std::string> &args,
                            const struct argument *templates) {
  out_args->clear();

  for (size_t i = 0; i < args.size(); i++) {
    const std::string &arg = args[i];
    const struct argument *templ = nullptr;
    for (size_t j = 0; templates[j].name[0] != 0; j++) {
      if (strcmp(arg.c_str(), templates[j].name) == 0) {
        templ = &templates[j];
        break;
      }
    }

    if (templ == nullptr) {
      fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
      return false;
    }

    if (out_args->find(arg) != out_args->end()) {
      fprintf(stderr, "Duplicate argument: %s\n", arg.c_str());
      return false;
    }

    if (templ->type == kBooleanArgument) {
      (*out_args)[arg] = "";
    } else {
      if (i + 1 >= args.size()) {
        fprintf(stderr, "Missing argument for option: %s\n", arg.c_str());
        return false;
      }
      (*out_args)[arg] = args[++i];
    }
  }

  for (size_t j = 0; templates[j].name[0] != 0; j++) {
    const struct argument *templ = &templates[j];
    if (templ->type == kRequiredArgument &&
        out_args->find(templ->name) == out_args->end()) {
      fprintf(stderr, "Missing value for required argument: %s\n", templ->name);
      return false;
    }
  }

  return true;
}

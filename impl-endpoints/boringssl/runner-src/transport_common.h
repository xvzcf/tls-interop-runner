// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#ifndef BORINGSSL_RUNNER_COMMON_H
#define BORINGSSL_RUNNER_COMMON_H

#include <openssl/ssl.h>
#include <string.h>

#include <string>

// Connect sets |*out_sock| to be a socket connected to the destination given
// in |hostname_and_port|, which should be of the form "www.example.com:123".
// It returns true on success and false otherwise.
bool Connect(int *out_sock, const std::string &hostname_and_port);

class Listener {
 public:
  Listener() {}
  ~Listener();

  // Init initializes the listener to listen on |port|, which should be of the
  // form "123".
  bool Init(const uint16_t &port);

  // Accept sets |*out_sock| to be a socket connected to the listener.
  bool Accept(int *out_sock);

 private:
  int server_sock_ = -1;

  Listener(const Listener &) = delete;
  Listener &operator=(const Listener &) = delete;
};

bool VersionFromString(uint16_t *out_version, const std::string &version);

void PrintConnectionInfo(BIO *bio, const SSL *ssl);

bool SocketSetNonBlocking(int sock, bool is_non_blocking);

// PrintSSLError prints information about the most recent SSL error to stderr.
// |ssl_err| must be the output of |SSL_get_error| and the |SSL| object must be
// connected to socket from |Connect|.
void PrintSSLError(FILE *file, const char *msg, int ssl_err, int ret);

#endif  // !BORINGSSL_RUNNER_COMMON_H

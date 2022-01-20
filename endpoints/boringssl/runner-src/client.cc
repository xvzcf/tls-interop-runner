// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#include <openssl/base.h>

#include <stdio.h>

#include <sys/select.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "internal.h"
#include "transport_common.h"

static const char *g_server_url = "example.com:4433";

static FILE *g_keylog_file = nullptr;
static const char *g_keylog_filename = "/test-outputs/client_keylog";

static void KeyLogCallback(const SSL *ssl, const char *line) {
  (void)ssl;
  fprintf(g_keylog_file, "%s\n", line);
  fflush(g_keylog_file);
}

static bool DoConnection(SSL *ssl) {
  int sock = -1;
  if (!Connect(&sock, g_server_url)) {
    return false;
  }

  bssl::UniquePtr<BIO> bio(BIO_new_socket(sock, BIO_CLOSE));
  SSL_set_bio(ssl, bio.get(), bio.get());
  bio.release();

  int ret = SSL_connect(ssl);
  if (ret != 1) {
    int ssl_err = SSL_get_error(ssl, ret);
    PrintSSLError(stderr, "Error while connecting", ssl_err, ret);
    return false;
  }

  fprintf(stdout, "Connected.\n");
  bssl::UniquePtr<BIO> bio_stdout(BIO_new_fp(stdout, BIO_NOCLOSE));
  PrintConnectionInfo(bio_stdout.get(), ssl);

  return true;
}

unsigned int DoClient(std::string testcase) {
  fprintf(stderr, "Testcase unsupported.\n");
  return 64;
}

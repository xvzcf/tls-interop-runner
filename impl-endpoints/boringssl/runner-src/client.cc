/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

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
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

  g_keylog_file = fopen(g_keylog_filename, "a");
  if (g_keylog_file == nullptr) {
    perror("fopen");
    return 1;
  }
  SSL_CTX_set_keylog_callback(ctx.get(), KeyLogCallback);

  if (testcase == "dc") {
    if (!SSL_CTX_load_verify_locations(ctx.get(), "/test-inputs/root.crt",
                                       nullptr)) {
      fprintf(stderr, "Failed to load root certificates.\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }
    SSL_CTX_set_verify(
        ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    SSL_set_tlsext_host_name(ssl.get(), "example.com");
    SSL_enable_delegated_credentials(ssl.get(), true);

    if (!DoConnection(ssl.get())) {
      return 1;
    }

    if (!SSL_delegated_credential_used_for_certificate_verify(ssl.get())) {
      fprintf(stderr, "Delegated credential not used.\n");
      return 1;
    }

    return 0;
  } else {
    fprintf(stderr, "Testcase unsupported.\n");
    return 64;
  }
}

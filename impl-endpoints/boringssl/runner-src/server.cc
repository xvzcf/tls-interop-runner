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

#include <memory>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "internal.h"
#include "transport_common.h"

static const uint16_t g_listen_on_port = 4433;

static FILE *g_keylog_file = nullptr;
static const char *g_keylog_filename = "/test-outputs/server_keylog";

static void KeyLogCallback(const SSL *ssl, const char *line) {
  (void)ssl;
  fprintf(g_keylog_file, "%s\n", line);
  fflush(g_keylog_file);
}

static bool DoListen(SSL *ssl) {
  Listener listener;
  if (!listener.Init(g_listen_on_port)) {
    return false;
  }

  int sock = -1;
  if (!listener.Accept(&sock)) {
    return false;
  }

  BIO *bio = BIO_new_socket(sock, BIO_CLOSE);
  SSL_set_bio(ssl, bio, bio);

  int ret = SSL_accept(ssl);
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

unsigned int DoServer(std::string testcase) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

  g_keylog_file = fopen(g_keylog_filename, "a");
  if (g_keylog_file == nullptr) {
    perror("fopen");
    return 1;
  }
  SSL_CTX_set_keylog_callback(ctx.get(), KeyLogCallback);

  if (testcase == "dc") {
    if (!SSL_CTX_use_PrivateKey_file(ctx.get(), "/test-inputs/example.key",
                                     SSL_FILETYPE_PEM)) {
      fprintf(stderr, "Failed to load private key.\n");
      return 1;
    }
    if (!SSL_CTX_use_certificate_chain_file(ctx.get(),
                                            "/test-inputs/example.crt")) {
      fprintf(stderr, "Failed to load cert.\n");
      return 1;
    }
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    SSL_set_tlsext_host_name(ssl.get(), "example.com");

    SSL_enable_delegated_credentials(ssl.get(), true);
    std::vector<uint8_t> dc, dc_priv_raw;
    if (!ReadDelegatedCredential(&dc, &dc_priv_raw, "/test-inputs/dc.txt")) {
      return false;
    }
    CBS dc_cbs(bssl::Span<const uint8_t>(dc.data(), dc.size()));
    CBS pkcs8_cbs(
        bssl::Span<const uint8_t>(dc_priv_raw.data(), dc_priv_raw.size()));

    bssl::UniquePtr<EVP_PKEY> dc_priv(EVP_parse_private_key(&pkcs8_cbs));
    if (!dc_priv) {
      fprintf(stderr, "failed to parse delegated credential private key.\n");
      return false;
    }

    bssl::UniquePtr<CRYPTO_BUFFER> dc_buf(
        CRYPTO_BUFFER_new_from_CBS(&dc_cbs, nullptr));
    if (!SSL_set1_delegated_credential(ssl.get(), dc_buf.get(), dc_priv.get(),
                                       nullptr)) {
      fprintf(stderr, "SSL_set1_delegated_credential failed.\n");
      return false;
    }

    if (!DoListen(ssl.get())) {
      return 1;
    }
    return 0;
  } else {
    fprintf(stderr, "Testcase unsupported.\n");
    return 64;
  }
}

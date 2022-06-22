// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#include <openssl/base.h>

#include <memory>

#include <openssl/err.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "internal.h"
#include "transport_common.h"

static const uint16_t g_listen_on_port = 4433;

static FILE *g_keylog_file = nullptr;
static const char *g_keylog_filename = "server_keylog";

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

  if (testcase == "ech-accept") {
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
    SSL_set_tlsext_host_name(ssl.get(), "client-facing.com");

    // Load the ECH private key
    std::string ech_key_path = "/ech_key_only";
    ScopedFILE ech_key_file(fopen(ech_key_path.c_str(), "rb"));
    std::vector<uint8_t> ech_key_b64;
    std::vector<uint8_t> ech_key;
    if (ech_key_file == nullptr || !ReadAll(&ech_key_b64, ech_key_file.get()) ||
        !DecodeBase64(&ech_key, &ech_key_b64)) {
      fprintf(stderr, "Error reading %s\n", ech_key_path.c_str());
      return 1;
    }

    // Load the ECHConfig.
    std::string ech_config_path = "/ech_config";
    ScopedFILE ech_config_file(fopen(ech_config_path.c_str(), "rb"));
    std::vector<uint8_t> ech_config_b64;
    std::vector<uint8_t> ech_config;
    if (ech_config_file == nullptr ||
        !ReadAll(&ech_config_b64, ech_config_file.get()) ||
        !DecodeBase64(&ech_config, &ech_config_b64)) {
      fprintf(stderr, "Error reading %s\n", ech_config_path.c_str());
      return 1;
    }

    bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
    bssl::ScopedEVP_HPKE_KEY key;
    if (!keys || !EVP_HPKE_KEY_init(key.get(), EVP_hpke_x25519_hkdf_sha256(),
                                    ech_key.data(), ech_key.size())) {
      fprintf(stderr, "EVP_HPKE_KEY_init failed.\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }
    if (!SSL_ECH_KEYS_add(keys.get(),
                          /*is_retry_config=*/1, ech_config.data(),
                          ech_config.size(), key.get())) {
      fprintf(stderr, "SSL_ECH_KEYS_add failed.\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }
    if (!SSL_CTX_set1_ech_keys(ctx.get(), keys.get())) {
      fprintf(stderr, "SSL_CTX_set1_ech_keys failed.\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }

    if (!DoListen(ssl.get())) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
    if (!SSL_ech_accepted(ssl.get())) {
      fprintf(stderr, "ECH was not negotiated.\n");
      return 1;
    }
    if (SSL_shutdown(ssl.get()) == -1) {
      fprintf(stderr, "Shutdown failed.\n");
      return 1;
    }
    return 0;
  } else if (testcase == "dc") {
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

    std::vector<uint8_t> dc, dc_priv_raw;
    if (!ReadDelegatedCredential(&dc, &dc_priv_raw, "/test-inputs/dc.txt")) {
      return 1;
    }
    CBS dc_cbs(bssl::Span<const uint8_t>(dc.data(), dc.size()));
    CBS pkcs8_cbs(
        bssl::Span<const uint8_t>(dc_priv_raw.data(), dc_priv_raw.size()));

    bssl::UniquePtr<EVP_PKEY> dc_priv(EVP_parse_private_key(&pkcs8_cbs));
    if (!dc_priv) {
      fprintf(stderr, "failed to parse delegated credential private key.\n");
      return 1;
    }

    bssl::UniquePtr<CRYPTO_BUFFER> dc_buf(
        CRYPTO_BUFFER_new_from_CBS(&dc_cbs, nullptr));
    if (!SSL_set1_delegated_credential(ssl.get(), dc_buf.get(), dc_priv.get(),
                                       nullptr)) {
      fprintf(stderr, "SSL_set1_delegated_credential failed.\n");
      return 1;
    }

    if (!DoListen(ssl.get())) {
      fprintf(stderr, "DoListen() failed.\n");
      return 1;
    }
    if (!SSL_delegated_credential_used(ssl.get())) {
      fprintf(stderr, "Delegated credential was not sent by server.\n");
      return 1;
    }
    if (SSL_shutdown(ssl.get()) == -1) {
      fprintf(stderr, "Shutdown failed.\n");
      return 1;
    }

    return 0;
  } else {
    fprintf(stderr, "Testcase unsupported.\n");
    return 64;
  }
}

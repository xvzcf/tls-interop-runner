// SPDX-FileCopyrightText: 2014 Google Inc.
// SPDX-License-Identifier: ISC

#include <openssl/base.h>

#include <string>
#include <vector>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "internal.h"
#include "transport_common.h"

using socket_result_t = ssize_t;
static int closesocket(int sock) { return close(sock); }

static inline void *OPENSSL_memset(void *dst, int c, size_t n) {
  if (n == 0) {
    return dst;
  }

  return memset(dst, c, n);
}

static void SplitHostPort(std::string *out_hostname, std::string *out_port,
                          const std::string &hostname_and_port) {
  size_t colon_offset = hostname_and_port.find_last_of(':');
  const size_t bracket_offset = hostname_and_port.find_last_of(']');
  std::string hostname, port;

  // An IPv6 literal may have colons internally, guarded by square brackets.
  if (bracket_offset != std::string::npos &&
      colon_offset != std::string::npos && bracket_offset > colon_offset) {
    colon_offset = std::string::npos;
  }

  if (colon_offset == std::string::npos) {
    *out_hostname = hostname_and_port;
    *out_port = "443";
  } else {
    *out_hostname = hostname_and_port.substr(0, colon_offset);
    *out_port = hostname_and_port.substr(colon_offset + 1);
  }
}

static std::string GetLastSocketErrorString() { return strerror(errno); }

static void PrintSocketError(const char *function) {
  std::string error = GetLastSocketErrorString();
  fprintf(stderr, "%s: %s\n", function, error.c_str());
}

// Connect sets |*out_sock| to be a socket connected to the destination given
// in |hostname_and_port|, which should be of the form "www.example.com:123".
// It returns true on success and false otherwise.
bool Connect(int *out_sock, const std::string &hostname_and_port) {
  std::string hostname, port;
  SplitHostPort(&hostname, &port, hostname_and_port);

  // Handle IPv6 literals.
  if (hostname.size() >= 2 && hostname[0] == '[' &&
      hostname[hostname.size() - 1] == ']') {
    hostname = hostname.substr(1, hostname.size() - 2);
  }

  struct addrinfo hint, *result;
  OPENSSL_memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;

  int ret = getaddrinfo(hostname.c_str(), port.c_str(), &hint, &result);
  if (ret != 0) {
    const char *error = gai_strerror(ret);
    fprintf(stderr, "getaddrinfo returned: %s\n", error);
    return false;
  }

  bool ok = false;
  char buf[256];

  *out_sock =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (*out_sock < 0) {
    PrintSocketError("socket");
    goto out;
  }

  switch (result->ai_family) {
    case AF_INET: {
      struct sockaddr_in *sin =
          reinterpret_cast<struct sockaddr_in *>(result->ai_addr);
      fprintf(stderr, "Connecting to %s:%d\n",
              inet_ntop(result->ai_family, &sin->sin_addr, buf, sizeof(buf)),
              ntohs(sin->sin_port));
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *sin6 =
          reinterpret_cast<struct sockaddr_in6 *>(result->ai_addr);
      fprintf(stderr, "Connecting to [%s]:%d\n",
              inet_ntop(result->ai_family, &sin6->sin6_addr, buf, sizeof(buf)),
              ntohs(sin6->sin6_port));
      break;
    }
  }

  if (connect(*out_sock, result->ai_addr, result->ai_addrlen) != 0) {
    PrintSocketError("connect");
    goto out;
  }
  ok = true;

out:
  freeaddrinfo(result);
  return ok;
}

Listener::~Listener() {
  if (server_sock_ >= 0) {
    closesocket(server_sock_);
  }
}

bool Listener::Init(const uint16_t &port) {
  if (server_sock_ >= 0) {
    return false;
  }

  struct sockaddr_in6 addr;
  OPENSSL_memset(&addr, 0, sizeof(addr));

  addr.sin6_family = AF_INET6;
  addr.sin6_addr = IN6ADDR_ANY_INIT;
  addr.sin6_port = htons(port);

  const int enable = 1;

  server_sock_ = socket(addr.sin6_family, SOCK_STREAM, 0);
  if (server_sock_ < 0) {
    PrintSocketError("socket");
    return false;
  }

  if (setsockopt(server_sock_, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable,
                 sizeof(enable)) < 0) {
    PrintSocketError("setsockopt");
    return false;
  }

  if (bind(server_sock_, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    PrintSocketError("connect");
    return false;
  }

  listen(server_sock_, SOMAXCONN);
  return true;
}

bool Listener::Accept(int *out_sock) {
  struct sockaddr_in6 addr;
  socklen_t addr_len = sizeof(addr);
  *out_sock = accept(server_sock_, (struct sockaddr *)&addr, &addr_len);
  return *out_sock >= 0;
}

void PrintConnectionInfo(BIO *bio, const SSL *ssl) {
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

  BIO_printf(bio, "  Version: %s\n", SSL_get_version(ssl));
  BIO_printf(bio, "  Resumed session: %s\n",
             SSL_session_reused(ssl) ? "yes" : "no");
  BIO_printf(bio, "  Cipher: %s\n", SSL_CIPHER_standard_name(cipher));
  uint16_t curve = SSL_get_curve_id(ssl);
  if (curve != 0) {
    BIO_printf(bio, "  ECDHE curve: %s\n", SSL_get_curve_name(curve));
  }
  uint16_t sigalg = SSL_get_peer_signature_algorithm(ssl);
  if (sigalg != 0) {
    BIO_printf(bio, "  Signature algorithm: %s\n",
               SSL_get_signature_algorithm_name(
                   sigalg, SSL_version(ssl) != TLS1_2_VERSION));
  }
  BIO_printf(bio, "  Secure renegotiation: %s\n",
             SSL_get_secure_renegotiation_support(ssl) ? "yes" : "no");
  BIO_printf(bio, "  Extended master secret: %s\n",
             SSL_get_extms_support(ssl) ? "yes" : "no");

  const uint8_t *next_proto;
  unsigned next_proto_len;
  SSL_get0_next_proto_negotiated(ssl, &next_proto, &next_proto_len);
  BIO_printf(bio, "  Next protocol negotiated: %.*s\n", next_proto_len,
             next_proto);

  const uint8_t *alpn;
  unsigned alpn_len;
  SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
  BIO_printf(bio, "  ALPN protocol: %.*s\n", alpn_len, alpn);

  const char *host_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (host_name != nullptr && SSL_is_server(ssl)) {
    BIO_printf(bio, "  Client sent SNI: %s\n", host_name);
  }

  if (!SSL_is_server(ssl)) {
    const uint8_t *ocsp_staple;
    size_t ocsp_staple_len;
    SSL_get0_ocsp_response(ssl, &ocsp_staple, &ocsp_staple_len);
    BIO_printf(bio, "  OCSP staple: %s\n", ocsp_staple_len > 0 ? "yes" : "no");

    const uint8_t *sct_list;
    size_t sct_list_len;
    SSL_get0_signed_cert_timestamp_list(ssl, &sct_list, &sct_list_len);
    BIO_printf(bio, "  SCT list: %s\n", sct_list_len > 0 ? "yes" : "no");
  }

  BIO_printf(
      bio, "  Early data: %s\n",
      (SSL_early_data_accepted(ssl) || SSL_in_early_data(ssl)) ? "yes" : "no");

  // Print the server cert subject and issuer names.
  bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(ssl));
  if (peer != nullptr) {
    BIO_printf(bio, "  Cert subject: ");
    X509_NAME_print_ex(bio, X509_get_subject_name(peer.get()), 0,
                       XN_FLAG_ONELINE);
    BIO_printf(bio, "\n  Cert issuer: ");
    X509_NAME_print_ex(bio, X509_get_issuer_name(peer.get()), 0,
                       XN_FLAG_ONELINE);
    BIO_printf(bio, "\n");
  }
}

void PrintSSLError(FILE *file, const char *msg, int ssl_err, int ret) {
  switch (ssl_err) {
    case SSL_ERROR_SSL:
      fprintf(file, "%s: %s\n", msg, ERR_reason_error_string(ERR_peek_error()));
      break;
    case SSL_ERROR_SYSCALL:
      if (ret == 0) {
        fprintf(file, "%s: peer closed connection\n", msg);
      } else {
        std::string error = GetLastSocketErrorString();
        fprintf(file, "%s: %s\n", msg, error.c_str());
      }
      break;
    case SSL_ERROR_ZERO_RETURN:
      fprintf(file, "%s: received close_notify\n", msg);
      break;
    default:
      fprintf(file, "%s: unexpected error: %s\n", msg,
              SSL_error_description(ssl_err));
  }
  ERR_print_errors_fp(file);
}

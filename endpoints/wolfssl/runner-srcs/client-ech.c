/* client-ech-local.c
 *
 * Copyright (C) 2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* socket includes */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* mmap */
#include <sys/mman.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 4433

#define CERT_FILE "/test-inputs/root.crt"

#ifdef HAVE_ECH
int main(void) {
  int sockfd;
  struct hostent *he;
  struct sockaddr_in servAddr;
  char buff[256];
  size_t len;
  int ret;
  const char *privateName = "client-facing.com";
  int privateNameLen = strlen(privateName);

  char *echConfigPath = "/test-inputs/ech_configs";
  int echConfigFd;
  int echConfigLen;
  void *echConfigData;

  /* declare wolfSSL objects */
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;

  /* Create a socket that uses an internet IPv4 address,
   * Sets the socket to be stream based (TCP),
   * 0 means choose the default protocol. */
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create the socket\n");
    ret = -1;
    goto end;
  }

  /* Initialize the server address struct with zeros */
  memset(&servAddr, 0, sizeof(servAddr));

  /* Fill in the server address */
  servAddr.sin_family = AF_INET;           /* using IPv4      */
  servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

  he = gethostbyname("example.com");
  if (he == NULL) {
    ret = -1;
    goto end;
  }
  memcpy(&servAddr.sin_addr, he->h_addr_list[0], he->h_length);

  /* Connect to the server */
  if ((ret = connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr))) ==
      -1) {
    fprintf(stderr, "ERROR: failed to connect\n");
    goto end;
  }

  /*---------------------------------*/
  /* Start of wolfSSL initialization and configuration */
  /*---------------------------------*/
  /* Initialize wolfSSL */
  if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: Failed to initialize the library\n");
    goto socket_cleanup;
  }

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    ret = -1;
    goto socket_cleanup;
  }

  /* Load client certificates into WOLFSSL_CTX */
  if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)) !=
      SSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
            CERT_FILE);
    goto ctx_cleanup;
  }

  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
    ret = -1;
    goto ctx_cleanup;
  }

  /* Load and set ECH Config */
  echConfigFd = open(echConfigPath, O_RDONLY);
  if (echConfigFd == -1) {
    fprintf(stderr, "ERROR: Failed to open ECH config.");
    ret = -1;
    goto cleanup;
  }

  echConfigLen = lseek(echConfigFd, 0, SEEK_END);
  if (echConfigLen == 0) {
    fprintf(stderr, "ERROR: Failed to read ECH config (len = 0).");
    ret = -1;
    goto cleanup;
  }

  echConfigData = mmap(0, echConfigLen, PROT_READ, MAP_PRIVATE, echConfigFd, 0);
  if (echConfigData == NULL) {
    fprintf(stderr, "ERROR: Failed to read ECH config.");
    ret = -1;
    goto cleanup;
  }

  if (wolfSSL_SetEchConfigsBase64(ssl, echConfigData, echConfigLen) !=
      WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: Failed to wolfSSL_SetEchConfigsBase64\n");
    ret = -1;
    goto cleanup;
  }

  if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, privateName, privateNameLen) !=
      WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: Failed to wolfSSL_UseSNI\n");
    ret = -1;
    goto cleanup;
  }

  /* Attach wolfSSL to the socket */
  if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
    fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
    goto cleanup;
  }

  if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to connect to server\n");
    goto cleanup;
  }

  /* Get a message for the server from stdin */
  printf("Message for server: ");
  memset(buff, 0, sizeof(buff));
  if (fgets(buff, sizeof(buff), stdin) == NULL) {
    fprintf(stderr, "ERROR: failed to get message for server\n");
    ret = -1;
    goto cleanup;
  }
  len = strnlen(buff, sizeof(buff));

  /* Send the message to the server */
  if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
    fprintf(stderr, "ERROR: failed to write entire message\n");
    fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int)len);
    goto cleanup;
  }

  /* Read the server data into our buff array */
  memset(buff, 0, sizeof(buff));
  if ((ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1) {
    fprintf(stderr, "ERROR: failed to read\n");
    goto cleanup;
  }

  /* Print to stdout any data the server sends */
  printf("Server: %s\n", buff);

  /* Bidirectional shutdown */
  while (wolfSSL_shutdown(ssl) == SSL_SHUTDOWN_NOT_DONE) {
    printf("Shutdown not complete\n");
  }

  printf("Shutdown complete\n");

  ret = 0;

  /* Cleanup and return */
cleanup:
  wolfSSL_free(ssl); /* Free the wolfSSL object                  */
ctx_cleanup:
  wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
socket_cleanup:
  close(sockfd); /* Close the connection to the server       */
end:
  return ret; /* Return reporting a success               */
}
#else
int main(void) {
  printf("Please build wolfssl with ./configure --enable-ech\n");
  return 1;
}
#endif

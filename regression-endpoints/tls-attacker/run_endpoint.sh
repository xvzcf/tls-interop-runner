#!/bin/sh
set -e

if [ "$ROLE" = "client" ]; then
    echo "Running tls-attacker client."
    echo "Server params: $CLIENT_PARAMS"
    echo "Test case: $TESTCASE"

    cd /tls-attacker/apps
    # java -jar Attacks.jar padding_oracle -connect server:4433
    # java -jar TLS-Client.jar -connect server:4433 -cipher TLS_RSA_WITH_AES_256_CBC_SHA -version TLS11
    java -jar TLS-Client.jar -connect server:4433 -cipher TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 -version TLS12
else
    echo "Running tls-attacker server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"

    cd /tls-attacker/apps
    java -jar TLS-Server.jar -port 4433
fi

#!/bin/bash
set -e

# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

sh /setup-routes.sh

DB_DIR="db"
P12_PASS="runner"
PORT=4433

rm -rf nss_testdata
mkdir nss_testdata

if [ "$TESTCASE" = "ech-accept" ] || [ "$TESTCASE" = "ech-reject" ]; then
    # Create a PKCS8 file for the ECH keypair
    python3 /ech_key_converter.py /test-inputs/ech_key nss_testdata/ech_key_converted

    # Create pfx files for pk12util
    openssl pkcs12 -export -out nss_testdata/root.pfx -name root.com -inkey /test-inputs/root.key -in /test-inputs/root.crt -passout pass:"$P12_PASS"
    openssl pkcs12 -export -out nss_testdata/example.pfx -name example.com -inkey /test-inputs/example.key -in /test-inputs/example.crt -passout pass:"$P12_PASS"
    openssl pkcs12 -export -out nss_testdata/client-facing.pfx -name client-facing.com -inkey /test-inputs/client-facing.key -in /test-inputs/client-facing.crt -passout pass:"$P12_PASS"
else
    echo "Test case not supported."
    return 64
fi

# Import certs and keys
certs=("example" "client-facing" "root")
for i in "${certs[@]}"
do
   pk12util -i nss_testdata/"$i".pfx -d "$DB_DIR" -W "$P12_PASS"

   # Trust the root
   if [ "$i" = "root" ]; then
     certutil -A -n "$i".com -t "C,C,C" -i /test-inputs/"$i".crt -d "$DB_DIR"
   fi
done

if [ "$ROLE" = "client" ]; then
    echo "Running NSS client."
    echo "Client params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    echo "GET / HTTP/1.0" > req.txt
    if [ "$TESTCASE" = "ech-reject" ]; then
      ECH_CONFIGS=$(</test-inputs/ech_configs_invalid)

      # Default cert verifier (which is used by tstclnt) is not ECH-aware.
      # Override failures since the hostnames won't match.
      tstclnt -d "$DB_DIR" -h example.com -p "$PORT" -N "$ECH_CONFIGS" -A req.txt -o &> err.txt || true
      ECH_CONFIGS=$(sed '4q;d' err.txt)
      if [ "$ECH_CONFIGS" != "$(</test-inputs/ech_configs)" ]; then
        echo "Unexpected error:"
        cat err.txt
      else
        echo "Aborted the connection as expected"
      fi
    else
      ECH_CONFIGS=$(</test-inputs/ech_configs)
      tstclnt -d "$DB_DIR" -h example.com -p "$PORT" -N "$ECH_CONFIGS" -A req.txt
    fi
else
    echo "Running NSS server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    ECH_KEY=$(<nss_testdata/ech_key_converted)
    selfserv -a example.com -n example.com -a client-facing.com -n client-facing.com -p "$PORT" -d "$DB_DIR" -X "$ECH_KEY"
fi

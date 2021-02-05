#!/bin/bash
set -e

sh /setup-routes.sh

DB_DIR="db"
P12_PASS="runner"
PORT=4433

rm -rf nss_testdata
mkdir nss_testdata

if [ "$TESTCASE" = "ech-accept" ]; then
    # Create a PKCS8 file for the ECH keypair
    python3 /ech_key_converter.py testdata/ech_key nss_testdata/ech_key_converted

    # Create pfx files for pk12util
    openssl pkcs12 -export -out nss_testdata/root.pfx -name root.com -inkey testdata/root.key -in testdata/root.crt -passout pass:"$P12_PASS"
    openssl pkcs12 -export -out nss_testdata/example.pfx -name example.com -inkey testdata/example.key -in testdata/example.crt -passout pass:"$P12_PASS"
    openssl pkcs12 -export -out nss_testdata/client-facing.pfx -name client-facing.com -inkey testdata/client-facing.key -in testdata/client-facing.crt -passout pass:"$P12_PASS"
else
    echo "Test case not supported."
    return true
fi

# Import certs and keys
certs=("example" "client-facing" "root")
for i in "${certs[@]}"
do
   pk12util -i nss_testdata/"$i".pfx -d "$DB_DIR" -W "$P12_PASS"

   # Trust the root
   if [ "$i" = "root" ]; then
     certutil -A -n "$i".com -t "C,C,C" -i testdata/"$i".crt -d "$DB_DIR"
   fi
done

if [ "$ROLE" = "client" ]; then
    echo "Running NSS client."
    echo "Client params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    ECH_CONFIGS=$(<testdata/ech_configs)
    echo "GET / HTTP/1.0" > req.txt
    tstclnt -d "$DB_DIR" -h example.com -p "$PORT" -N "$ECH_CONFIGS" -A req.txt
else
    echo "Running NSS server."
    echo "Server params: $SERVER_PARAMS"
    echo "Test case: $TESTCASE"
    ECH_KEY=$(<nss_testdata/ech_key_converted)
    selfserv -a example.com -n example.com -a client-facing.com -n client-facing.com -p "$PORT" -d "$DB_DIR" -X "$ECH_KEY"
fi

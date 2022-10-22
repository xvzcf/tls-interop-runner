#!/bin/sh
set -e

sh /setup-routes.sh

PORT=4433

rm -rf fizz_testdata
mkdir fizz_testdata

if [ "$TESTCASE" = "ech-accept" ] || [ "$TESTCASE" = "ech-reject" ]; then
    # Convert ECH config to fizz tool format first
    echo "Running fizz ECH test case, preparing..."
    python3 /ech_key_converter.py /test-inputs/ech_key fizz_testdata/key fizz_testdata/config
    #python3 /ech_key_converter.py /test-inputs/ech_configs_invalid -n fizz_testdata/invalid_config
    cat /test-inputs/client-facing.crt /test-inputs/root.crt > fizz_testdata/client-facing-chain.crt
    cat /test-inputs/example.crt /test-inputs/root.crt > fizz_testdata/example-chain.crt
else
    echo "Test case not supported."
    return 64
fi

if [ "$ROLE" = "client" ]; then
    echo "Test case: $TESTCASE"
    if [ "$TESTCASE" = "ech-accept" ]; then
        /output/fizz/bin/fizz client -connect "example.com:$PORT" -cafile  -echconfigs fizz_testdata/config
#        if ! grep -q "Encrypted client hello (ECH) enabled" out.txt; then
#            echo "Unexpected error: ECH wasn't enabled!"
#            cat out.txt
#            return 1
#        fi
    else
        echo "TODO: Implement rejection handling"
        return 64
    fi
else
    echo "Test case: $TESTCASE"
    /output/fizz/bin/fizz server -echconfigs fizz_testdata/config -echprivatekey fizz_testdata/key -cert fizz_testdata/client-facing-chain.crt -cert fizz_testdata/example-chain.crt -key /test-inputs/example.key -key /test-inputs/client-facing.key -accept "$PORT"
fi

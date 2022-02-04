#!/bin/bash -ex

if [[ ! -d "bin/pkcs11test" ]]; then
  git clone https://github.com/google/pkcs11test bin/pkcs11test
fi

rm -f bin/server.sock
cd bin/pkcs11test && make && cd -
./bin/example-p11-kit-server \
  --priv example/priv.pem \
  --pub example/pub.pem \
  --cert example/cert.pem \
  bin/server.sock 2>bin/out &
SERVER_PID="$!"
sleep 2

export P11_KIT_SERVER_ADDRESS="unix:path=${PWD}/bin/server.sock"
./bin/pkcs11test/pkcs11test -m /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so || true

kill "$SERVER_PID"
wait "$SERVER_PID"

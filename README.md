# PKCS #11 modules in Go without cgo

[![Go Reference](https://pkg.go.dev/badge/github.com/google/go-p11-kit/p11kit.svg)](https://pkg.go.dev/github.com/google/go-p11-kit/p11kit)

This project implements [p11-kit RPC server protocol][p11-kit-rpc], allowing Go
programs to act as a PKCS #11 module without the need for cgo. Clients load the
p11-kit-client.so shared library, then communicate over RPC to the Go server.

```
       ------------------------
       | client (e.g. Chrome) |
       ------------------------
                 |
     (PKCS #11 - shared library)
                 ↓ 
        ---------------------
        | p11-kit-client.so |
        ---------------------
                 |
        (RPC over unix socket)
                 ↓ 
---------------------------------------
| github.com/google/go-p11-kit/p11kit |
---------------------------------------
```

[p11-kit-rpc]: https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html

## Demo

The example directory contains a demo server that reads keys and certificates
from disk and serves them on a unix socket. To build and start the server, run
the following commands:

```
go build -o bin/example-p11-kit-server ./example/example-p11-kit-server
./bin/example-p11-kit-server --priv example/priv.pem --pub example/pub.pem --cert example/cert.pem
```

The server will print out an environment variable to set similar to:

```
export P11_KIT_SERVER_ADDRESS=unix:path=/tmp/1056705225/p11kit.sock
```

In another shell, export the environment variable, and use p11-kit-client.so
to query the example server:

```
$ export P11_KIT_SERVER_ADDRESS=unix:path=/tmp/1056705225/p11kit.sock
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --list-slots
Available slots:
Slot 0 (0x1): example-slot
  token label        : example
  token manufacturer : go-p11-kit
  token model        : example-server
  token flags        : token initialized, readonly
  hardware version   : 0.1
  firmware version   : 0.1
  serial num         : 12345678
  pin min/max        : 0/0
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --list-objects
Using slot 0 with a present token (0x1)
Certificate Object; type = X.509 cert
  subject:    DN: CN=test
Private Key Object; RSA
  Usage:      decrypt, sign
  Access:     none
Public Key Object; RSA 256 bits
  Usage:      encrypt, verify
  Access:     none
```

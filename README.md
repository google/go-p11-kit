# PKCS #11 modules in Go without cgo

[![Go Reference](https://pkg.go.dev/badge/github.com/google/go-p11kit/p11kit.svg)](https://pkg.go.dev/github.com/google/go-p11kit/p11kit)

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

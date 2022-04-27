// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/google/go-p11-kit/p11kit"
)

func usage() {
	fmt.Fprint(os.Stderr, `Usage: example-p11-kit-server [flags] [unix socket path]

An example p11-kit server that can serve on disk files as a PKCS #11 module.

Flags:

    --cert  Path to a file containing a PEM encoded certificate.
    --priv  Path to a file containing a PEM encoded private key.
    --pub   Path to a file containing a PEM encoded public key.
    --stdio Serve a single connection over stdio, intended for p11-kit's 'remote' module entries.

`)
}

func parsePrivateKey(b *pem.Block) (crypto.PrivateKey, error) {
	switch b.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(b.Bytes)
	default:
		return x509.ParsePKCS8PrivateKey(b.Bytes)
	}
}

func parsePublicKey(b *pem.Block) (crypto.PublicKey, error) {
	switch b.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(b.Bytes)
	default:
		return x509.ParsePKIXPublicKey(b.Bytes)
	}
}

func main() {
	flag.Usage = usage

	var (
		certFiles []string
		privFiles []string
		pubFiles  []string
	)
	flag.Func("cert", "", func(file string) error {
		certFiles = append(certFiles, file)
		return nil
	})
	flag.Func("priv", "", func(file string) error {
		privFiles = append(privFiles, file)
		return nil
	})
	flag.Func("pub", "", func(file string) error {
		pubFiles = append(pubFiles, file)
		return nil
	})
	stdio := flag.Bool("stdio", false, "Serve a single connection over stdio.")
	flag.Parse()

	var unixPath string
	switch len(flag.Args()) {
	case 0:
	case 1:
		unixPath = flag.Args()[0]
	default:
		usage()
		os.Exit(1)
	}

	var objs []p11kit.Object
	for _, f := range certFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("Reading certificate file %s: %v", f, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatalf("Decoding certificate file %s: %v", f, err)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Parsing certificate file %s: %v", f, err)
		}
		obj, err := p11kit.NewX509CertificateObject(cert)
		if err != nil {
			log.Fatalf("Creating object from certificate file %s: %v", f, err)
		}
		objs = append(objs, obj)
	}

	for _, f := range privFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("Reading private key file %s: %v", f, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatalf("Decoding private key file %s: %v", f, err)
		}
		priv, err := parsePrivateKey(block)
		if err != nil {
			log.Fatalf("Parsing private key file %s: %v", f, err)
		}
		obj, err := p11kit.NewPrivateKeyObject(priv)
		if err != nil {
			log.Fatalf("Creating object from private key file %s: %v", f, err)
		}
		objs = append(objs, obj)
	}

	for _, f := range pubFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("Reading public key file %s: %v", f, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			log.Fatalf("Decoding public key file %s: %v", f, err)
		}
		pub, err := parsePublicKey(block)
		if err != nil {
			log.Fatalf("Parsing public key file %s: %v", f, err)
		}
		obj, err := p11kit.NewPublicKeyObject(pub)
		if err != nil {
			log.Fatalf("Creating object from private key file %s: %v", f, err)
		}
		objs = append(objs, obj)
	}

	slot := p11kit.Slot{
		ID:              0x01,
		Description:     "example-slot",
		Label:           "example",
		Manufacturer:    "go-p11-kit",
		Model:           "example-server",
		Serial:          "12345678",
		HardwareVersion: p11kit.Version{Major: 0, Minor: 1},
		FirmwareVersion: p11kit.Version{Major: 0, Minor: 1},
		Objects:         objs,
	}

	h := p11kit.Handler{
		Manufacturer:   "go-p11-kit",
		Library:        "example-server",
		LibraryVersion: p11kit.Version{Major: 0, Minor: 1},
		Slots:          []p11kit.Slot{slot},
	}

	if *stdio {
		rw := struct {
			io.Reader
			io.Writer
		}{os.Stdin, os.Stdout}
		if err := h.Handle(&rw); err != nil {
			log.Fatalf("Handling over stdio: %v", err)
		}
		os.Exit(0)
	}

	if unixPath == "" {
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			log.Fatalf("Creating temp directory: %v", err)
		}
		defer os.RemoveAll(tempDir)

		unixPath = filepath.Join(tempDir, "p11kit.sock")
	}

	l, err := net.Listen("unix", unixPath)
	if err != nil {
		log.Fatalf("Listening on %s: %v", unixPath, err)
	}
	defer l.Close()

	fmt.Println("export P11_KIT_SERVER_ADDRESS=unix:path=" + unixPath)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("Accepting new connection: %v", err)
		}
		go func() {
			if err := h.Handle(conn); err != nil {
				log.Printf("Handling connection: %v", err)
			}
			conn.Close()
		}()
	}
}

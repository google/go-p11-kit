package p11kit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	p11KitClientPath    = "/usr/local/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
	p11KitEnvServerAddr = "P11_KIT_SERVER_ADDRESS"
	p11KitEnvServerPID  = "P11_KIT_SERVER_PID"
)

func testRequiresP11Tools(t *testing.T) {
	//	t.Skip("skipping e2e tests")
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not available, skipping test")
	}
	if _, err := os.Stat(p11KitClientPath); err != nil {
		t.Skip("p11-kit-client.so not available, skipping test")
	}
}

func newListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "p11kit.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listening for unix socket: %v", err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Closing unix socket: %v", err)
		}
	})
	return l, socketPath
}

const (
	// openssl req -x509 -subj '/CN=test' -sha256 -nodes -days 365 -newkey rsa:2048 --keyout=/dev/stdout
	testRSAPrivKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyoFC9EU4DKKbD
0RYV8mQvDElg2t7WcWzYyAJk97bF1+S/iAgNk5lg2HxsuN18V8TWxQuIaOUIsU0i
WFwXdh28ndsAlpoJeFr5/9zNinVAaXWrtoAzqUzNgb3/0WUlm1OToG1pMaJn3/Lv
Ba1vh0NrwSuHN2zd/sVz9E0HjjWxoCt8TsYAUHrO/81131qnT2qOYdFsRhn5QzOi
FwgLiBIIPAhEgI5Ph0FFo+YbHzpUbLR3QXxH2ldrYmqULol90SO0X0F1eh7n9wco
NF9QU2Z4NwBtSNqmVyQvNz5S8GyrnfXaGcVT3LY8azyYC0mkx/tVhwbZPAokkoir
JLhHbdprAgMBAAECggEBAKMgONuRFBdaZoFpTqwYQlmc9N4Yw2w/BVIrxdQDTMz8
zpADYKdVZbrFuUtowAwv8zjXliKq+I6prHFzFBbw7VM1La0p295OJXctrK2ghlee
d7Gq5wVG1TbQB3258o8XfInS9lgc1d3a7PZPzwWNF4suS9weR7OsWRH9xuLhgjOF
Nd1xZuv9x+6wHnbBld2y6B9I8CVPL/kW3A8G1YmsMewpJxInhCqNG9ku6JFb20z8
faylNhnFTk7H1llT1G3snWm+wx/NCz1FgW5nX0Gd0jGWrh0wH9eXYYq9f/yA1y1X
6xMIsu1Awp9SGyo09ZYYbnNG55J71ayiwt6va/hHQJECgYEA1g7YOrj9gv8QnN1j
spFQrFYJx3CcHXDHaqhKPeJoO+gkl2zr++eiqYXRxd6MyZqJiz4cW26yaFWFHq4Q
zJHEWiWCKT7woqQt4/i+xxaxKvP3W5m6UPcI2e8eATYdOC9MWeLUx5DAd/1Mo0gq
/BRytYMwxC8zHuX1IN62/4zLuV0CgYEA1aA2eegU1d13ug7E2R23eXTYzpy8Magh
532vK7vOAyOGpZoe6K4NpSlvI+wsRuyVYPGdf6OQLnD4ugTRe3Qvb9FIIKVExPqC
5nJ/z3egCxURVqMGXAD49d25MRfcGEEW+2GUeSw5N/D+pRldbwre7tamuySXoMp0
/r2Kyaj8/mcCgYBkC1AYMfmaTefPyNEd1jjkMtojMohkYh9xw/He9oBM73SaqTep
5lrp7DdcyWT3nJiIUaEjQptzk/TBoA0N71rb3wf0iwwgl6czE0Dm/74SGzASyciA
qtSiNtXJLyd86O5AXHmiRA8QhXxaHBKq+kuadhRGvOChokxs7mqNCZr1qQKBgGA9
hm1TThevZ6Htx2cdCSxxpL8oQ2yHl4any8QDHuOxHJb8oRIoX8NZsFVZr/Tf3shG
8bKwKGOTx6peQ1W/2SMiAMGcUyf+x/wz9zqrZPG5Mw958IKAeaiilCz219Qhds4X
fwE8GCcIrmAI1lwRZK/rCkBjUuBAdYbSM3V4aUnfAoGAZTzoSXssyZO5JjLiKKgc
YJD9zKdKY78feYXWQCAFfB9lIrEHkW1QuUHHIvrUBJRdMS+rmKkgE1I7vaPZ+DZk
n2xX/H3BANE823ZoVDJWpzscN1iqlYyF8/Np0rgGyTA4aS1OzsOyqPeNxMw2WQm3
HlP1OV+0JiuKr1Afu2Ca5WQ=
-----END PRIVATE KEY-----`
	testRSACert = `-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUF9z+XaTIstx5LOFAVtPW22QLht4wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMjAxMTQyMTQyMzVaFw0yMzAxMTQyMTQy
MzVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCyoFC9EU4DKKbD0RYV8mQvDElg2t7WcWzYyAJk97bF1+S/iAgNk5lg2Hxs
uN18V8TWxQuIaOUIsU0iWFwXdh28ndsAlpoJeFr5/9zNinVAaXWrtoAzqUzNgb3/
0WUlm1OToG1pMaJn3/LvBa1vh0NrwSuHN2zd/sVz9E0HjjWxoCt8TsYAUHrO/811
31qnT2qOYdFsRhn5QzOiFwgLiBIIPAhEgI5Ph0FFo+YbHzpUbLR3QXxH2ldrYmqU
Lol90SO0X0F1eh7n9wcoNF9QU2Z4NwBtSNqmVyQvNz5S8GyrnfXaGcVT3LY8azyY
C0mkx/tVhwbZPAokkoirJLhHbdprAgMBAAGjUzBRMB0GA1UdDgQWBBRRZSjdUZ2T
3oh+yH0sh8Aa4LdRgDAfBgNVHSMEGDAWgBRRZSjdUZ2T3oh+yH0sh8Aa4LdRgDAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCtX0JjSRbE4U1KXblw
EKtV9Sp3vOY335UeYAZ9XkdAPlfTOx0UF9yGt2elOMLQJE5e5CEAIdm0bEhawWje
LgHSRURjcGf52agBYIVR61kZRgTBthIOKWwy/7pOZ3mrswW3Aj1HkAXHtpECxYOd
w1vlsdjMVkph7Q3BwYePP5SZ/N3jFKwptGhHeBFYRHoBuGBfqrOq1vqPIvtbaYQF
2Okp4PZFTp3g7rjuDflP5RS4SjgwHxPGhgz2QSrNgzbQ49+Gw9+ywM/zeXZGdKNt
kdvOoL5VnzG5buw3BwXOEb6QGZCBMa0kXYCbGIa0SQ+3Md8TMFNo9fHteQ47dUYX
x+4U
-----END CERTIFICATE-----`

	// openssl req -x509 -subj '/CN=test' -sha256 -nodes -days 365 -newkey ec -pkeyopt ec_paramgen_curve:P-256 --keyout=/dev/stdout
	testECDSAPrivKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGP5IFr7U7klzbqVe
man/Aa5pmt7ACfQpxhf7yoVvZVOhRANCAASh6q01mGb+bJklMwLw2/ioXTbiHhI8
U93xfG0atMwO7C0UjcegEip85KjQpcF5/BQIzp78lUx0ut8c0q/HqHO6
-----END PRIVATE KEY-----`
	testECDSACert = `-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUW64CYBM36fgHEL3WHBM97bRrDxwwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yMjAxMjYxOTE0MjlaFw0yMzAxMjYxOTE0Mjla
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASh6q01
mGb+bJklMwLw2/ioXTbiHhI8U93xfG0atMwO7C0UjcegEip85KjQpcF5/BQIzp78
lUx0ut8c0q/HqHO6o1MwUTAdBgNVHQ4EFgQUJBY0DVgllZRJZ7qATbxrgNCY3Fsw
HwYDVR0jBBgwFoAUJBY0DVgllZRJZ7qATbxrgNCY3FswDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEAqJHZtkM3Bp9A70fyf6a0Pz32G57kI00NcghT
v6PMfQMCIQCH3a31qlv3pnnG3jF4AGteFlvm/cAW/0Yzj7+nniUEyg==
-----END CERTIFICATE-----`
)

func parseCert(t *testing.T, data string) Object {
	t.Helper()
	pemCert, _ := pem.Decode([]byte(data))
	if pemCert == nil {
		t.Fatalf("Failed to decode test certificate")
	}
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		t.Fatalf("Parse test certificate: %v", err)
	}
	certObj, err := NewX509CertificateObject(cert)
	if err != nil {
		t.Fatalf("Creating x509 certificate object: %v", err)
	}
	return certObj
}

func parsePub(t *testing.T, data string) Object {
	t.Helper()
	pemPriv, _ := pem.Decode([]byte(data))
	if pemPriv == nil {
		t.Fatalf("Failed to decode test key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(pemPriv.Bytes)
	if err != nil {
		t.Fatalf("Parse test key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("Private key doesn't implement crypto.Signer: %T", priv)
	}
	pubObj, err := NewPublicKeyObject(signer.Public())
	if err != nil {
		t.Fatalf("Creating pub key object: %v", err)
	}
	return pubObj
}

func parsePriv(t *testing.T, data string) Object {
	t.Helper()
	pemPriv, _ := pem.Decode([]byte(data))
	if pemPriv == nil {
		t.Fatalf("Failed to decode test key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(pemPriv.Bytes)
	if err != nil {
		t.Fatalf("Parse test key: %v", err)
	}
	privObj, err := NewPrivateKeyObject(priv)
	if err != nil {
		t.Fatalf("Creating pub key object: %v", err)
	}
	return privObj
}

func newTestServer(t *testing.T) *Handler {
	rsaCertObj := parseCert(t, testRSACert)
	rsaPubObj := parsePub(t, testRSAPrivKey)
	rsaPrivObj := parsePriv(t, testRSAPrivKey)
	ecdsaCertObj := parseCert(t, testECDSACert)
	ecdsaPubObj := parsePub(t, testECDSAPrivKey)
	ecdsaPrivObj := parsePriv(t, testECDSAPrivKey)

	rsaCertObj.SetLabel("foo")
	rsaPubObj.SetLabel("foo")
	rsaPrivObj.SetLabel("fookey")
	ecdsaCertObj.SetLabel("bar")
	ecdsaPubObj.SetLabel("bar")
	ecdsaPrivObj.SetLabel("barkey")

	objects := []Object{
		rsaCertObj,
		rsaPubObj,
		rsaPrivObj,
	}
	objects2 := []Object{
		ecdsaCertObj,
		ecdsaPubObj,
		ecdsaPrivObj,
	}

	hwVersion := Version{0x01, 0x01}
	fwVersion := Version{0x02, 0x02}
	return &Handler{
		Manufacturer: "test",
		Library:      "test_lib",
		LibraryVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
		Slots: []Slot{
			{
				ID:              0x01,
				Label:           "slot-0x01",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x01",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
				Objects:         objects,
			},
			{
				ID:              0x02,
				Label:           "slot-0x02",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x02",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
				Objects:         objects2,
			},
		},
	}
}

func TestPKCS11Tool(t *testing.T) {
	testRequiresP11Tools(t)
	tempDir := t.TempDir()
	inData := filepath.Join(tempDir, "sign-in")
	outData := filepath.Join(tempDir, "sign-out")

	// Create an ASN.1 DigestInfo object.

	digest := sha256.Sum256([]byte("hello, world"))
	digestInfo := append([]byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20,
	}, digest[:]...)
	if err := os.WriteFile(inData, digestInfo, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	inPSSData := filepath.Join(tempDir, "sign-pss-in")
	outPSSData := filepath.Join(tempDir, "sign-pss-out")
	if err := os.WriteFile(inPSSData, digest[:], 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	inECDSAData := filepath.Join(tempDir, "sign-ecdsa-in")
	outECDSAData := filepath.Join(tempDir, "sign-ecdsa-out")
	if err := os.WriteFile(inECDSAData, digest[:], 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		name  string
		args  []string
		after func(t *testing.T)
	}{
		{"ListSlots", []string{"--list-slots"}, nil},
		{"ListTokenSlots", []string{"--list-token-slots"}, nil},
		{"ListObjects", []string{"--list-objects"}, nil},
		{"Sign", []string{
			"--sign",
			"--slot=0x01",
			"--label=fookey",
			"--input-file=" + inData,
			"--output-file=" + outData,
			"-m", "RSA-PKCS",
		}, func(t *testing.T) {
			obj := parsePub(t, testRSAPrivKey)
			pub, ok := obj.pub.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("object doesn't contain public key")
			}
			sig, err := os.ReadFile(outData)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
		}},
		{"SignPSS", []string{
			"--sign",
			"--slot=0x01",
			"--label=fookey",
			"--input-file=" + inPSSData,
			"--output-file=" + outPSSData,
			"-m", "RSA-PKCS-PSS",
			"--hash-algorithm=SHA256",
		}, func(t *testing.T) {
			obj := parsePub(t, testRSAPrivKey)
			pub, ok := obj.pub.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("object doesn't contain public key")
			}
			sig, err := os.ReadFile(outPSSData)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
		}},
		{"SignECDSA", []string{
			"--sign",
			"--slot=0x02",
			"--input-file=" + inECDSAData,
			"--output-file=" + outECDSAData,
			"-m", "ECDSA",
		}, func(t *testing.T) {
			obj := parsePub(t, testECDSAPrivKey)
			pub, ok := obj.pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("object doesn't contain public key")
			}
			sig, err := os.ReadFile(outECDSAData)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Errorf("failed to verify signature")
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l, path := newListener(t)

			h := newTestServer(t)

			errCh := make(chan error)
			go func() {
				done := make(chan struct{})
				defer close(done)
				go func() {
					select {
					case <-done:
					case <-time.After(time.Second * 10):
						l.Close()
					}
				}()
				conn, err := l.Accept()
				if err != nil {
					errCh <- err
					return
				}
				conn.SetDeadline(time.Now().Add(time.Second * 10))
				errCh <- h.Handle(conn)
			}()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "pkcs11-tool",
				append([]string{
					"--verbose",
					"--module", p11KitClientPath,
				}, test.args...)...)
			cmd.Env = append(os.Environ(),
				"P11_KIT_DEBUG=all",
				p11KitEnvServerPID+"="+strconv.Itoa(os.Getpid()),
				p11KitEnvServerAddr+"=unix:path="+path,
			)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Errorf("command failed: %v\nstderr=%s\nstdout=%s", err, &stderr, &stdout)
			} else {
				t.Logf("%s", &stdout)
			}
			if err := <-errCh; err != nil {
				t.Errorf("handle error: %v", err)
			}
			if test.after != nil {
				test.after(t)
			}
		})
	}
}

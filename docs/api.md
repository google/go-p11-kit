# API Design

The PKCS #11 specification is designed as a C-like API. Because of this, it
uses patterns that aren't necessary required for Go, such as functions that ask
for the length of an array instead of just passing an array directly:

```c
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
	CK_BBOOL tokenPresent,
	CK_SLOT_ID_PTR pSlotList,
	CK_ULONG_PTR pulCount
);
```

In addition, there are many features in PKCS #11 that 99% of users never need
or will implement identically every time. Turning objects into their associated
CK_ATTRIBUTEs, session handling, object searches, etc.

## Proposal

Instead of providing a 1-to-1 mapping of PKCS #11 functions, this package will
implement a higher level API that can be used to drive the complexities of a
PKCS #11 module.

```go
package p11kit

type Version struct {
	Major, Minor byte
}

type Slot struct {
	ID uint64

	Label        string
	Manufacturer string
	Model        string
	SerialNumber string

	HardwareVersion Version
	FirmwareVersion Version

	Objects []Object
}

type Object struct {
	Label string
	// contains filtered or unexported fields
}

func NewX509CertificateObject(cert *x509.Certificate) (*Object, error) { ... }
func NewPublicKeyObject(pub crypto.PublicKey) (*Object, error) { ... }
func NewPrivateKeyObject(priv crypto.PrivateKey) (*Object, error) { ... }

type Server struct {
	Manufacturer   string
	Library        string
	LibraryVersion Version

	Slots []Slot
}

func (h *Handler) Handle(rw io.ReadWriter) error { ... } 
```

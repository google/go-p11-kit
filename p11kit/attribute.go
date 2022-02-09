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

package p11kit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"
)

// Object represents a single entity, such as a certificate, or private key.
type Object struct {
	id uint64

	attributes []attribute

	pub  crypto.PublicKey
	priv crypto.Signer
}

func (o *Object) supports(m mechanism) error {
	if o.priv == nil {
		return fmt.Errorf("object is not a private key: %w", errMechanismInvalid)
	}
	switch o.priv.Public().(type) {
	case *ecdsa.PublicKey:
		if m.typ == ckmECDSA {
			return nil
		}
		return fmt.Errorf("ECDSA key doesn't support mechanism 0x%08x: %w", m.typ, errMechanismInvalid)
	case *rsa.PublicKey:
		if m.typ == ckmRSAPKCS || m.typ == ckmRSAPKCSPSS {
			return nil
		}
		return fmt.Errorf("RSA key doesn't support mechanism 0x%08x: %w", m.typ, errMechanismInvalid)
	default:
		return fmt.Errorf("private key is neither RSA or ECDSA: %T", o.priv.Public())
	}
}

func (o *Object) matches(tmpl attribute) bool {
	for _, a := range o.attributes {
		if a.typ != tmpl.typ {
			continue
		}
		return bytes.Equal(a.value(), tmpl.value())
	}
	return false
}

// SetLabel applies a label to the object, allowing clients to differentiate
// between different objects of the same type on a single slot.
func (o *Object) SetLabel(label string) {
	o.attributes = append(o.attributes, attribute{
		typ: attributeLabel, bytes: []byte(label),
	})
}

func (o *Object) attributeValue(typ attributeType) (attribute, bool) {
	for _, a := range o.attributes {
		if a.typ == typ {
			return a, true
		}
	}
	return attribute{}, false
}

func (o *Object) sign(m mechanism, data []byte) ([]byte, error) {
	if o.priv == nil {
		return nil, fmt.Errorf("object isn't a private key: %w", errKeyHandleInvalid)
	}

	switch m.typ {
	case ckmRSAPKCS:
		return signRSAPKCS(o.priv, m, data)
	case ckmRSAPKCSPSS:
		return signRSAPKCSPSS(o.priv, m, data)
	case ckmECDSA:
		return signECDSA(o.priv, m, data)
	default:
		return nil, errMechanismInvalid
	}
}

var hashLengths = map[int]crypto.Hash{
	crypto.SHA256.Size(): crypto.SHA256,
	crypto.SHA384.Size(): crypto.SHA384,
	crypto.SHA512.Size(): crypto.SHA512,
}

func signECDSA(priv crypto.Signer, m mechanism, data []byte) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850452
	if !m.noParams() {
		return nil, fmt.Errorf("CKM_ECDSA does not take any parameters: %w", errArgumentsBad)
	}
	return priv.Sign(rand.Reader, data, crypto.Hash(0))
}

// These are ASN1 DER structures:
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
//
// For performance, we don't use the generic ASN1 encoder. Rather, we
// precompute a prefix of the digest value that makes a valid ASN1 DER string
// with the correct contents.
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func signRSAPKCS(priv crypto.Signer, m mechanism, data []byte) ([]byte, error) {
	// https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894635
	if !m.noParams() {
		return nil, fmt.Errorf("CKM_RSA_PKCS does not take any parameters: %w", errArgumentsBad)
	}
	for hash, prefix := range hashPrefixes {
		if !bytes.HasPrefix(data, prefix) {
			continue
		}
		return priv.Sign(rand.Reader, bytes.TrimPrefix(data, prefix), hash)
	}
	return nil, fmt.Errorf("unrecognized hash data: %w", errArgumentsBad)
}

func signRSAPKCSPSS(priv crypto.Signer, m mechanism, data []byte) ([]byte, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894638
	p, ok := m.params.(rsaPKCSPSSParams)
	if !ok {
		return nil, fmt.Errorf("expected PSS params, got %T", m.params)
	}
	var (
		mgf  uint64
		hash crypto.Hash
	)
	switch p.hashAlg {
	case ckmSHA256:
		hash = crypto.SHA256
		mgf = ckgMGF1SHA256
	case ckmSHA384:
		hash = crypto.SHA384
		mgf = ckgMGF1SHA384
	case ckmSHA512:
		hash = crypto.SHA512
		mgf = ckgMGF1SHA512
	default:
		return nil, fmt.Errorf("unsupported hash algorithm 0x%08x: %w", p.hashAlg, errMechanismParamInvalid)
	}
	if mgf != p.mgf {
		return nil, fmt.Errorf("provided mgf 0x%08x doesn't match provided hash %s: %w", p.mgf, hash, errMechanismParamInvalid)
	}
	opts := &rsa.PSSOptions{
		SaltLength: int(p.saltLen),
		Hash:       hash,
	}
	return priv.Sign(rand.Reader, data, opts)
}

const (
	// https://github.com/Pkcs11Interop/PKCS11-SPECS/blob/master/v2.20/headers/pkcs11t.h#L427-L433
	ckcX509 uint64 = 0

	// https://github.com/Pkcs11Interop/PKCS11-SPECS/blob/master/v2.20/headers/pkcs11t.h#L334-L345
	ckoData        uint64 = 0x00000000
	ckoCertificate uint64 = 0x00000001
	ckoPublicKey   uint64 = 0x00000002
	ckoPrivateKey  uint64 = 0x00000003

	// https://github.com/Pkcs11Interop/PKCS11-SPECS/blob/master/v2.20/headers/pkcs11t.h#L370-L380
	ckkRSA   uint64 = 0x00000000
	ckkECDSA uint64 = 0x00000003
)

var (
	maxUint64     *big.Int
	maxUint64Once sync.Once
)

func newObjectID() (uint64, error) {
	maxUint64Once.Do(func() {
		var n big.Int
		maxUint64 = n.SetUint64(math.MaxUint64)
	})
	id, err := rand.Int(rand.Reader, maxUint64)
	if err != nil {
		return 0, err
	}
	return id.Uint64(), nil
}

// RFC 5480, 2.1.1.1. Named Curve
//
// secp224r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
// secp256r1 OBJECT IDENTIFIER ::= {
//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//   prime(1) 7 }
//
// secp384r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
// secp521r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// NewPrivateKeyObject creates a PKCS #11 object from a private key.
//
// priv is expected to implement crypto.Signer, and optionally crypto.Decrypter.
func NewPrivateKeyObject(priv crypto.PrivateKey) (Object, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return Object{}, fmt.Errorf("private key doesn't implement crypto.Signer: %T", priv)
	}
	id, err := newObjectID()
	if err != nil {
		return Object{}, err
	}
	attrs, err := newKeyObject(signer.Public(), true)
	if err != nil {
		return Object{}, err
	}
	return Object{id: id, attributes: attrs, priv: signer}, nil
}

// NewPublicKeyObject creates a PKCS #11 object from a public key.
//
// pub must be of underlying type *ecdsa.PublicKey or *rsa.PublicKey.
func NewPublicKeyObject(pub crypto.PublicKey) (Object, error) {
	id, err := newObjectID()
	if err != nil {
		return Object{}, err
	}
	attrs, err := newKeyObject(pub, false)
	if err != nil {
		return Object{}, err
	}
	return Object{id: id, attributes: attrs, pub: pub}, nil
}

var (
	bFalse *byte
	bTrue  *byte
)

func init() {
	// https://go.dev/issues/45624
	f := byte(0)
	t := byte(1)
	bFalse = &f
	bTrue = &t
}

func newKeyObject(pub crypto.PublicKey, isPrivate bool) ([]attribute, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959718
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
	objectClass := ckoPublicKey
	verify := bTrue
	if isPrivate {
		objectClass = ckoPrivateKey
		verify = bFalse
	}

	attrs := []attribute{
		{typ: attributeClass, ulong: &objectClass},  // CKA_CLASS
		{typ: attributeVerifyRecover, byte: bFalse}, // CKA_VERIFY_RECOVER
		{typ: attributeWrap, byte: bFalse},          // CKA_WRAP
		{typ: attributeVerify, byte: verify},        // CKA_VERIFY
	}

	if isPrivate {
		attrs = append(attrs,
			attribute{typ: attributeExtractable, byte: bFalse}, // CKA_EXTRACTABLE
			attribute{typ: attributeSign, byte: bTrue},         // CKA_SIGN
		)
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850449
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850450
		var oid asn1.ObjectIdentifier
		switch pub.Curve {
		case elliptic.P224():
			oid = oidNamedCurveP224
		case elliptic.P256():
			oid = oidNamedCurveP256
		case elliptic.P384():
			oid = oidNamedCurveP384
		case elliptic.P521():
			oid = oidNamedCurveP521
		default:
			return nil, fmt.Errorf("unsupported ecdsa curve: %v", pub.Curve.Params().Name)
		}
		params, err := asn1.Marshal(oid)
		if err != nil {
			return nil, fmt.Errorf("encoding ecdsa curve: %v", err)
		}

		keyType := ckkECDSA
		attrs = append(attrs,
			attribute{typ: attributeKeyType, ulong: &keyType}, // CKA_KEY_TYPE
			attribute{typ: attributeECParams, bytes: params},  // CKA_EC_PARAMS
		)
		if isPrivate {
			attrs = append(attrs,
				attribute{typ: attributeDecrypt, byte: bFalse}, // CKA_DECRYPT
				attribute{typ: attributeValue},                 // CKA_VALUE (empty)
			)
		} else {
			point := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
			attrs = append(attrs,
				attribute{typ: attributeEncrypt, byte: bFalse}, // CKA_ENCRYPT
				attribute{typ: attributeECPoint, bytes: point}, // CKA_EC_POINT
			)
		}
	case *rsa.PublicKey:
		// TODO(ericchiang): support CKA_ENCRYPT for RSA public keys.

		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850406
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850407
		size := uint64(pub.Size() * 8)
		e := big.NewInt(int64(pub.E))
		keyType := ckkRSA
		attrs = append(attrs,
			attribute{typ: attributeKeyType, ulong: &keyType},         // CKA_KEY_TYPE
			attribute{typ: attributeModulus, bytes: pub.N.Bytes()},    // CKA_MODULUS
			attribute{typ: attributeModulusBits, ulong: &size},        // CKA_MODULUS_BITS
			attribute{typ: attributePublicExponent, bytes: e.Bytes()}, // CKA_PUBLIC_EXPONENT
		)
		if isPrivate {
			attrs = append(attrs,
				attribute{typ: attributeDecrypt, byte: bTrue}, // CKA_DECRYPT
				attribute{typ: attributePrivateExponent},      // CKA_PRIVATE_EXPONENT (empty)
				attribute{typ: attributePrime1},               // CKA_PRIME_1 (empty)
				attribute{typ: attributePrime2},               // CKA_PRIME_2 (empty)
				attribute{typ: attributeExponent1},            // CKA_EXPONENT_1 (empty)
				attribute{typ: attributeExponent2},            // CKA_EXPONENT_2 (empty)
				attribute{typ: attributeCoefficient},          // CKA_COEFFICIENT (empty)
			)
		} else {
			attrs = append(attrs, attribute{typ: attributeEncrypt, byte: bTrue}) // CKA_ENCRYPT
		}
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}

	return attrs, nil
}

// NewX509CertificateObject creates a PKCS #11 X.509 certificate object.
func NewX509CertificateObject(cert *x509.Certificate) (Object, error) {
	id, err := newObjectID()
	if err != nil {
		return Object{}, err
	}
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959711
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959712
	certType := ckcX509
	objectClass := ckoCertificate
	return Object{
		id: id,
		attributes: []attribute{
			{typ: attributeClass, ulong: &objectClass},        // CKA_CLASS
			{typ: attributeCertificateType, ulong: &certType}, // CKA_CERTIFICATE_TYPE
			{typ: attributeSubject, bytes: cert.RawSubject},   // CKA_SUBJECT
			{typ: attributeIssuer, bytes: cert.RawIssuer},     // CKA_ISSUER
			{typ: attributeValue, bytes: cert.Raw},            // CKA_VALUE
		},
	}, nil
}

const (
	// https://github.com/Pkcs11Interop/PKCS11-SPECS/blob/master/v2.20/headers/pkcs11t.h
	ckmRSAPKCS    = 0x00000001
	ckmRSAPKCSPSS = 0x0000000D
	ckmECDSA      = 0x00001041
	ckmSHA256     = 0x00000250
	ckmSHA384     = 0x00000260
	ckmSHA512     = 0x00000270

	ckgMGF1SHA256 = 0x00000002
	ckgMGF1SHA384 = 0x00000003
	ckgMGF1SHA512 = 0x00000004
)

var mechanismToString = map[uint32]string{
	ckmRSAPKCS:    "CKM_RSA_PKCS",
	ckmRSAPKCSPSS: "CKM_RSA_PKCS_PSS",
	ckmECDSA:      "CKM_ECDSA",
}

type mechanism struct {
	typ    uint32
	params interface{}
}

func (m mechanism) noParams() bool {
	b, ok := m.params.([]byte)
	return ok && len(b) == 0
}

type rsaPKCSPSSParams struct {
	hashAlg uint64
	mgf     uint64
	saltLen uint64
}

func (m mechanism) String() string {
	if s, ok := mechanismToString[m.typ]; ok {
		return s
	}
	return fmt.Sprintf("CK_MECHANISM_TYPE(0x%08x)", m.typ)
}

// attribute represents a PKCS #11 attribute, a typed object with optional value.
type attribute struct {
	typ attributeType

	byte       *byte      // byte
	ulong      *uint64    // ulong
	mechanisms []uint64   // mechanism array
	date       *time.Time // date
	bytes      []byte     // byte array
}

type attributeTemplate struct {
	typ attributeType
	len uint32
}

// setDate decodes the value of the attribute into a CK_DATE value, returning if
// the operation was successful.
func (a attribute) setDate(year *int, month *time.Month, day *int) bool {
	if a.date == nil {
		return false
	}
	*year, *month, *day = a.date.Date()
	return true
}

// setUint64 decodes the value of the attribute into a uint64 value, returning if
// the operation was successful.
func (a attribute) setUint64(n *uint64) bool {
	if a.ulong == nil {
		return false
	}
	*n = *a.ulong
	return true
}

// setByte decodes the value of the attribute into a byte value, returning if
// the operation was successful.
func (a attribute) setByte(b *byte) bool {
	if a.byte == nil {
		return false
	}
	*b = *a.byte
	return true
}

const (
	attributeTypeByte = 1 + iota
	attributeTypeUlong
	attributeTypeMechanismArray
	attributeTypeDate
	attributeTypeByteArray
)

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L782
func (a attributeType) valueType() int {
	switch a {
	case attributeToken,
		attributePrivate,
		attributeTrusted,
		attributeSensitive,
		attributeEncrypt,
		attributeDecrypt,
		attributeWrap,
		attributeUnwrap,
		attributeSign,
		attributeSignRecover,
		attributeVerify,
		attributeVerifyRecover,
		attributeDerive,
		attributeExtractable,
		attributeLocal,
		attributeNeverExtractable,
		attributeAlwaysSensitive,
		attributeModifiable,
		attributeCopyable,
		attributeSecondaryAuth, /* deprecated */
		attributeAlwaysAuthenticate,
		attributeWrapWithTrusted,
		attributeResetOnInit,
		attributeHasReset,
		attributeColor:
		return attributeTypeByte
	case attributeClass,
		attributeCertificateType,
		attributeCertificateCategory,
		attributeJavaMIDPSecurityDomain,
		attributeKeyType,
		attributeModulusBits,
		attributePrimeBits,
		attributeSubprimeBits,
		attributeValueBits,
		attributeValueLen,
		attributeKeyGenMechanism,
		attributeAuthPINFlags, /* deprecated */
		attributeHWFeatureType,
		attributePixelX,
		attributePixelY,
		attributeResolution,
		attributeCharRows,
		attributeCharColumns,
		attributeBitsPerPixel,
		attributeMechanismType:
		return attributeTypeUlong
	case attributeWrapTemplate,
		attributeUnwrapTemplate:
		// TODO(ericchiang): support P11_RPC_VALUE_ATTRIBUTE_ARRAY
		return 0
	case attributeAllowedMechanisms:
		return attributeTypeMechanismArray
	case attributeStartDate,
		attributeEndDate:
		// return P11_RPC_VALUE_DATE;
		return attributeTypeDate
	case attributeLabel,
		attributeApplication,
		attributeValue,
		attributeObjectID,
		attributeIssuer,
		attributeSerialNumber,
		attributeACIssuer,
		attributeOwner,
		attributeAttrTypes,
		attributeURL,
		attributeHashOfSubjectPublicKey,
		attributeHashOfIssuerPublicKey,
		attributeCheckValue,
		attributeSubject,
		attributeID,
		attributeModulus,
		attributePublicExponent,
		attributePrivateExponent,
		attributePrime1,
		attributePrime2,
		attributeExponent1,
		attributeExponent2,
		attributeCoefficient,
		attributePrime,
		attributeSubprime,
		attributeBase,
		attributeECParams,
		attributeECPoint,
		attributeCharSets,
		attributeEncodingMethods,
		attributeMIMETypes,
		attributeRequiredCMSAttributes,
		attributeDefaultCMSAttributes,
		attributeSupportedCMSAttributes:
		return attributeTypeByteArray
	default:
		return 0
	}
}

func (a *attribute) value() []byte {
	if a.byte != nil {
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L890
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L901
		return []byte{*a.byte}
	}
	if a.ulong != nil {
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L891
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L919
		var b buffer
		b.addUint64(*a.ulong)
		return b.bytes()
	}
	if a.bytes != nil {
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L895
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L730
		var b buffer
		b.addByteArray(a.bytes)
		return b.bytes()
	}
	if a.date != nil {
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L894
		// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L998
		var b buffer
		b.addDate(*a.date)
		return b.bytes()
	}
	return nil
}

// attributeType indicates the meaning of the attribute values.
type attributeType uint32

// String returns the PKCS #11 spec name for the attribute type.
func (a attributeType) String() string {
	if s, ok := attributeString[a]; ok {
		return s
	}
	return fmt.Sprintf("attribute(0x%x)", uint64(a))
}

// Attribute types defined by the PKCS #11 specification.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959757
const (
	attributeClass                  attributeType = 0x00000000
	attributeToken                  attributeType = 0x00000001
	attributePrivate                attributeType = 0x00000002
	attributeLabel                  attributeType = 0x00000003
	attributeApplication            attributeType = 0x00000010
	attributeValue                  attributeType = 0x00000011
	attributeObjectID               attributeType = 0x00000012
	attributeCertificateType        attributeType = 0x00000080
	attributeIssuer                 attributeType = 0x00000081
	attributeSerialNumber           attributeType = 0x00000082
	attributeACIssuer               attributeType = 0x00000083
	attributeOwner                  attributeType = 0x00000084
	attributeAttrTypes              attributeType = 0x00000085
	attributeTrusted                attributeType = 0x00000086
	attributeCertificateCategory    attributeType = 0x00000087
	attributeJavaMIDPSecurityDomain attributeType = 0x00000088
	attributeURL                    attributeType = 0x00000089
	attributeHashOfSubjectPublicKey attributeType = 0x0000008a
	attributeHashOfIssuerPublicKey  attributeType = 0x0000008b
	attributeNameHashAlgorithm      attributeType = 0x0000008c
	attributeCheckValue             attributeType = 0x00000090
	attributeKeyType                attributeType = 0x00000100
	attributeSubject                attributeType = 0x00000101
	attributeID                     attributeType = 0x00000102
	attributeSensitive              attributeType = 0x00000103
	attributeEncrypt                attributeType = 0x00000104
	attributeDecrypt                attributeType = 0x00000105
	attributeWrap                   attributeType = 0x00000106
	attributeUnwrap                 attributeType = 0x00000107
	attributeSign                   attributeType = 0x00000108
	attributeSignRecover            attributeType = 0x00000109
	attributeVerify                 attributeType = 0x0000010a
	attributeVerifyRecover          attributeType = 0x0000010b
	attributeDerive                 attributeType = 0x0000010c
	attributeStartDate              attributeType = 0x00000110
	attributeEndDate                attributeType = 0x00000111
	attributeModulus                attributeType = 0x00000120
	attributeModulusBits            attributeType = 0x00000121
	attributePublicExponent         attributeType = 0x00000122
	attributePrivateExponent        attributeType = 0x00000123
	attributePrime1                 attributeType = 0x00000124
	attributePrime2                 attributeType = 0x00000125
	attributeExponent1              attributeType = 0x00000126
	attributeExponent2              attributeType = 0x00000127
	attributeCoefficient            attributeType = 0x00000128
	attributePrime                  attributeType = 0x00000130
	attributeSubprime               attributeType = 0x00000131
	attributeBase                   attributeType = 0x00000132
	attributePrimeBits              attributeType = 0x00000133
	attributeSubprimeBits           attributeType = 0x00000134
	attributeValueBits              attributeType = 0x00000160
	attributeValueLen               attributeType = 0x00000161
	attributeExtractable            attributeType = 0x00000162
	attributeLocal                  attributeType = 0x00000163
	attributeNeverExtractable       attributeType = 0x00000164
	attributeAlwaysSensitive        attributeType = 0x00000165
	attributeKeyGenMechanism        attributeType = 0x00000166
	attributeModifiable             attributeType = 0x00000170
	attributeCopyable               attributeType = 0x00000171
	attributeDestroyable            attributeType = 0x00000172
	attributeECDSAParams            attributeType = 0x00000180
	attributeECParams               attributeType = 0x00000180
	attributeECPoint                attributeType = 0x00000181
	attributeSecondaryAuth          attributeType = 0x00000200
	attributeAuthPINFlags           attributeType = 0x00000201
	attributeAlwaysAuthenticate     attributeType = 0x00000202
	attributeWrapWithTrusted        attributeType = 0x00000210
	attributeWrapTemplate           attributeType = 0x40000211
	attributeUnwrapTemplate         attributeType = 0x40000212
	attributeHWFeatureType          attributeType = 0x00000300
	attributeResetOnInit            attributeType = 0x00000301
	attributeHasReset               attributeType = 0x00000302
	attributePixelX                 attributeType = 0x00000400
	attributePixelY                 attributeType = 0x00000401
	attributeResolution             attributeType = 0x00000402
	attributeCharRows               attributeType = 0x00000403
	attributeCharColumns            attributeType = 0x00000404
	attributeColor                  attributeType = 0x00000405
	attributeBitsPerPixel           attributeType = 0x00000406
	attributeCharSets               attributeType = 0x00000480
	attributeEncodingMethods        attributeType = 0x00000481
	attributeMIMETypes              attributeType = 0x00000482
	attributeMechanismType          attributeType = 0x00000500
	attributeRequiredCMSAttributes  attributeType = 0x00000501
	attributeDefaultCMSAttributes   attributeType = 0x00000502
	attributeSupportedCMSAttributes attributeType = 0x00000503
	attributeAllowedMechanisms      attributeType = 0x40000600
	attributeVendorDefined          attributeType = 0x80000000
)

var attributeString = map[attributeType]string{
	attributeClass:                  "CKA_CLASS",
	attributeToken:                  "CKA_TOKEN",
	attributePrivate:                "CKA_PRIVATE",
	attributeLabel:                  "CKA_LABEL",
	attributeApplication:            "CKA_APPLICATION",
	attributeValue:                  "CKA_VALUE",
	attributeObjectID:               "CKA_OBJECT_ID",
	attributeCertificateType:        "CKA_CERTIFICATE_TYPE",
	attributeIssuer:                 "CKA_ISSUER",
	attributeSerialNumber:           "CKA_SERIAL_NUMBER",
	attributeACIssuer:               "CKA_AC_ISSUER",
	attributeOwner:                  "CKA_OWNER",
	attributeAttrTypes:              "CKA_ATTR_TYPES",
	attributeTrusted:                "CKA_TRUSTED",
	attributeCertificateCategory:    "CKA_CERTIFICATE_CATEGORY",
	attributeJavaMIDPSecurityDomain: "CKA_JAVA_MIDP_SECURITY_DOMAIN",
	attributeURL:                    "CKA_URL",
	attributeHashOfSubjectPublicKey: "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
	attributeHashOfIssuerPublicKey:  "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
	attributeNameHashAlgorithm:      "CKA_NAME_HASH_ALGORITHM",
	attributeCheckValue:             "CKA_CHECK_VALUE",
	attributeKeyType:                "CKA_KEY_TYPE",
	attributeSubject:                "CKA_SUBJECT",
	attributeID:                     "CKA_ID",
	attributeSensitive:              "CKA_SENSITIVE",
	attributeEncrypt:                "CKA_ENCRYPT",
	attributeDecrypt:                "CKA_DECRYPT",
	attributeWrap:                   "CKA_WRAP",
	attributeUnwrap:                 "CKA_UNWRAP",
	attributeSign:                   "CKA_SIGN",
	attributeSignRecover:            "CKA_SIGN_RECOVER",
	attributeVerify:                 "CKA_VERIFY",
	attributeVerifyRecover:          "CKA_VERIFY_RECOVER",
	attributeDerive:                 "CKA_DERIVE",
	attributeStartDate:              "CKA_START_DATE",
	attributeEndDate:                "CKA_END_DATE",
	attributeModulus:                "CKA_MODULUS",
	attributeModulusBits:            "CKA_MODULUS_BITS",
	attributePublicExponent:         "CKA_PUBLIC_EXPONENT",
	attributePrivateExponent:        "CKA_PRIVATE_EXPONENT",
	attributePrime1:                 "CKA_PRIME_1",
	attributePrime2:                 "CKA_PRIME_2",
	attributeExponent1:              "CKA_EXPONENT_1",
	attributeExponent2:              "CKA_EXPONENT_2",
	attributeCoefficient:            "CKA_COEFFICIENT",
	attributePrime:                  "CKA_PRIME",
	attributeSubprime:               "CKA_SUBPRIME",
	attributeBase:                   "CKA_BASE",
	attributePrimeBits:              "CKA_PRIME_BITS",
	attributeSubprimeBits:           "CKA_SUBPRIME_BITS",
	attributeValueBits:              "CKA_VALUE_BITS",
	attributeValueLen:               "CKA_VALUE_LEN",
	attributeExtractable:            "CKA_EXTRACTABLE",
	attributeLocal:                  "CKA_LOCAL",
	attributeNeverExtractable:       "CKA_NEVER_EXTRACTABLE",
	attributeAlwaysSensitive:        "CKA_ALWAYS_SENSITIVE",
	attributeKeyGenMechanism:        "CKA_KEY_GEN_MECHANISM",
	attributeModifiable:             "CKA_MODIFIABLE",
	attributeCopyable:               "CKA_COPYABLE",
	attributeDestroyable:            "CKA_DESTROYABLE",
	attributeECDSAParams:            "CKA_ECDSA_PARAMS",
	attributeECPoint:                "CKA_EC_POINT",
	attributeSecondaryAuth:          "CKA_SECONDARY_AUTH",
	attributeAuthPINFlags:           "CKA_AUTH_PIN_FLAGS",
	attributeAlwaysAuthenticate:     "CKA_ALWAYS_AUTHENTICATE",
	attributeWrapWithTrusted:        "CKA_WRAP_WITH_TRUSTED",
	attributeWrapTemplate:           "CKA_WRAP_TEMPLATE",
	attributeUnwrapTemplate:         "CKA_UNWRAP_TEMPLATE",
	attributeHWFeatureType:          "CKA_HW_FEATURE_TYPE",
	attributeResetOnInit:            "CKA_RESET_ON_INIT",
	attributeHasReset:               "CKA_HAS_RESET",
	attributePixelX:                 "CKA_PIXEL_X",
	attributePixelY:                 "CKA_PIXEL_Y",
	attributeResolution:             "CKA_RESOLUTION",
	attributeCharRows:               "CKA_CHAR_ROWS",
	attributeCharColumns:            "CKA_CHAR_COLUMNS",
	attributeColor:                  "CKA_COLOR",
	attributeBitsPerPixel:           "CKA_BITS_PER_PIXEL",
	attributeCharSets:               "CKA_CHAR_SETS",
	attributeEncodingMethods:        "CKA_ENCODING_METHODS",
	attributeMIMETypes:              "CKA_MIME_TYPES",
	attributeMechanismType:          "CKA_MECHANISM_TYPE",
	attributeRequiredCMSAttributes:  "CKA_REQUIRED_CMS_ATTRIBUTES",
	attributeDefaultCMSAttributes:   "CKA_DEFAULT_CMS_ATTRIBUTES",
	attributeSupportedCMSAttributes: "CKA_SUPPORTED_CMS_ATTRIBUTES",
	attributeAllowedMechanisms:      "CKA_ALLOWED_MECHANISMS",
	attributeVendorDefined:          "CKA_VENDOR_DEFINED",
}

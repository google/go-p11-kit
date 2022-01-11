package p11kit

import (
	"fmt"
	"time"
)

// Attribute represents a PKCS #11 attribute, a typed object with optional value.
type Attribute struct {
	typ   AttributeType
	value []byte

	b *byte      // byte
	n *uint64    // ulong
	m []uint64   // mechanism array
	d *time.Time // date
	a []byte     // byte array
}

// Type returns the type of the attribute.
func (a Attribute) Type() AttributeType {
	return a.typ
}

// IsSet returns if the attribute has a value.
func (a Attribute) IsSet() bool {
	return a.value != nil ||
		a.b != nil ||
		a.n != nil ||
		a.m != nil ||
		a.d != nil ||
		a.a != nil
}

// Bytes decodes the value of the attribute into a byte array, returning if
// the operation was successful.
func (a Attribute) Bytes(b []byte) bool {
	if a.a == nil {
		return false
	}
	b = a.a
	return true
}

// Date decodes the value of the attribute into a CK_DATE value, returning if
// the operation was successful.
func (a Attribute) Date(year *int, month *time.Month, day *int) bool {
	if a.d == nil {
		return false
	}
	*year, *month, *day = a.d.Date()
	return true
}

// Uint64 decodes the value of the attribute into a uint64 value, returning if
// the operation was successful.
func (a Attribute) Uint64(n *uint64) bool {
	if a.n == nil {
		return false
	}
	*n = *a.n
	return true
}

// Byte decodes the value of the attribute into a byte value, returning if
// the operation was successful.
func (a Attribute) Byte(b *byte) bool {
	if a.b == nil {
		return false
	}
	*b = *a.b
	return true
}

// NewAttribute returns an attribute of the given type with no value. Use the
// various Set methods to set the value.
//
// If set, the type of the value MUST match the type of the attribute. It's up
// to the caller to know which type holds what value.
//
// See:
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L782
func NewAttribute(t AttributeType) Attribute {
	return Attribute{typ: t}
}

// SetByte sets the value of the attribute to a single byte.
func (a *Attribute) SetByte(b byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L890
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L901
	a.value = []byte{b}
}

// SetBytes sets the value of the attribute to a byte array.
func (a *Attribute) SetBytes(arr []byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L895
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L1024
	var b buffer
	b.addByteArray(arr)
	a.value = b.bytes()
}

// SetUint64 sets the value of the attribute to a ulong.
func (a *Attribute) SetUint64(n uint64) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L891
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L919
	var b buffer
	b.addUint64(n)
	a.value = b.bytes()
}

// SetDate sets the value of the attribute to a CK_DATE.
func (a *Attribute) SetDate(year, month, day int) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L894
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L998
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	var b buffer
	b.addDate(t)
	a.value = b.bytes()
}

const (
	attributeTypeByte = 1 + iota
	attributeTypeUlong
	attributeTypeMechanismArray
	attributeTypeDate
	attributeTypeByteArray
)

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L782
func (a AttributeType) valueType() int {
	switch a {
	case AttributeToken,
		AttributePrivate,
		AttributeTrusted,
		AttributeSensitive,
		AttributeEncrypt,
		AttributeDecrypt,
		AttributeWrap,
		AttributeUnwrap,
		AttributeSign,
		AttributeSignRecover,
		AttributeVerify,
		AttributeVerifyRecover,
		AttributeDerive,
		AttributeExtractable,
		AttributeLocal,
		AttributeNeverExtractable,
		AttributeAlwaysSensitive,
		AttributeModifiable,
		AttributeCopyable,
		AttributeSecondaryAuth, /* deprecated */
		AttributeAlwaysAuthenticate,
		AttributeWrapWithTrusted,
		AttributeResetOnInit,
		AttributeHasReset,
		AttributeColor:
		return attributeTypeByte
	case AttributeClass,
		AttributeCertificateType,
		AttributeCertificateCategory,
		AttributeJavaMIDPSecurityDomain,
		AttributeKeyType,
		AttributeModulusBits,
		AttributePrimeBits,
		AttributeSubprimeBits,
		AttributeValueBits,
		AttributeValueLen,
		AttributeKeyGenMechanism,
		AttributeAuthPINFlags, /* deprecated */
		AttributeHWFeatureType,
		AttributePixelX,
		AttributePixelY,
		AttributeResolution,
		AttributeCharRows,
		AttributeCharColumns,
		AttributeBitsPerPixel,
		AttributeMechanismType:
		return attributeTypeUlong
	case AttributeWrapTemplate,
		AttributeUnwrapTemplate:
		// TODO(ericchiang): support P11_RPC_VALUE_ATTRIBUTE_ARRAY
		return 0
	case AttributeAllowedMechanisms:
		return attributeTypeMechanismArray
	case AttributeStartDate,
		AttributeEndDate:
		// return P11_RPC_VALUE_DATE;
		return attributeTypeDate
	case AttributeLabel,
		AttributeApplication,
		AttributeValue,
		AttributeObjectID,
		AttributeIssuer,
		AttributeSerialNumber,
		AttributeACIssuer,
		AttributeOwner,
		AttributeAttrTypes,
		AttributeURL,
		AttributeHashOfSubjectPublicKey,
		AttributeHashOfIssuerPublicKey,
		AttributeCheckValue,
		AttributeSubject,
		AttributeID,
		AttributeModulus,
		AttributePublicExponent,
		AttributePrivateExponent,
		AttributePrime1,
		AttributePrime2,
		AttributeExponent1,
		AttributeExponent2,
		AttributeCoefficient,
		AttributePrime,
		AttributeSubprime,
		AttributeBase,
		AttributeECParams,
		AttributeECPoint,
		AttributeCharSets,
		AttributeEncodingMethods,
		AttributeMIMETypes,
		AttributeRequiredCMSAttributes,
		AttributeDefaultCMSAttributes,
		AttributeSupportedCMSAttributes:
		return attributeTypeByteArray
	default:
		return 0
	}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L890
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L901
func newByteAttribute(t AttributeType, b byte) *Attribute {
	return &Attribute{typ: t, value: []byte{b}}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L891
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L919
func newUlongAttribute(t AttributeType, n uint64) *Attribute {
	var b buffer
	b.addUint64(n)
	return &Attribute{typ: t, value: b.bytes()}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L893
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L968
func newMechanismTypeArrayAttribute(t AttributeType, arr []uint64) *Attribute {
	var b buffer
	b.addUint32(uint32(len(arr)))
	for _, m := range arr {
		b.addUint64(m)
	}
	return &Attribute{typ: t, value: b.bytes()}
}

// AttributeType indicates the meaning of the attribute values.
type AttributeType uint32

// String returns the PKCS #11 spec name for the attribute type.
func (a AttributeType) String() string {
	if s, ok := attributeString[a]; ok {
		return s
	}
	return fmt.Sprintf("attribute(0x%x)", uint64(a))
}

// Attribute types defined by the PKCS #11 specification.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959757
const (
	AttributeClass                  AttributeType = 0x00000000
	AttributeToken                  AttributeType = 0x00000001
	AttributePrivate                AttributeType = 0x00000002
	AttributeLabel                  AttributeType = 0x00000003
	AttributeApplication            AttributeType = 0x00000010
	AttributeValue                  AttributeType = 0x00000011
	AttributeObjectID               AttributeType = 0x00000012
	AttributeCertificateType        AttributeType = 0x00000080
	AttributeIssuer                 AttributeType = 0x00000081
	AttributeSerialNumber           AttributeType = 0x00000082
	AttributeACIssuer               AttributeType = 0x00000083
	AttributeOwner                  AttributeType = 0x00000084
	AttributeAttrTypes              AttributeType = 0x00000085
	AttributeTrusted                AttributeType = 0x00000086
	AttributeCertificateCategory    AttributeType = 0x00000087
	AttributeJavaMIDPSecurityDomain AttributeType = 0x00000088
	AttributeURL                    AttributeType = 0x00000089
	AttributeHashOfSubjectPublicKey AttributeType = 0x0000008a
	AttributeHashOfIssuerPublicKey  AttributeType = 0x0000008b
	AttributeNameHashAlgorithm      AttributeType = 0x0000008c
	AttributeCheckValue             AttributeType = 0x00000090
	AttributeKeyType                AttributeType = 0x00000100
	AttributeSubject                AttributeType = 0x00000101
	AttributeID                     AttributeType = 0x00000102
	AttributeSensitive              AttributeType = 0x00000103
	AttributeEncrypt                AttributeType = 0x00000104
	AttributeDecrypt                AttributeType = 0x00000105
	AttributeWrap                   AttributeType = 0x00000106
	AttributeUnwrap                 AttributeType = 0x00000107
	AttributeSign                   AttributeType = 0x00000108
	AttributeSignRecover            AttributeType = 0x00000109
	AttributeVerify                 AttributeType = 0x0000010a
	AttributeVerifyRecover          AttributeType = 0x0000010b
	AttributeDerive                 AttributeType = 0x0000010c
	AttributeStartDate              AttributeType = 0x00000110
	AttributeEndDate                AttributeType = 0x00000111
	AttributeModulus                AttributeType = 0x00000120
	AttributeModulusBits            AttributeType = 0x00000121
	AttributePublicExponent         AttributeType = 0x00000122
	AttributePrivateExponent        AttributeType = 0x00000123
	AttributePrime1                 AttributeType = 0x00000124
	AttributePrime2                 AttributeType = 0x00000125
	AttributeExponent1              AttributeType = 0x00000126
	AttributeExponent2              AttributeType = 0x00000127
	AttributeCoefficient            AttributeType = 0x00000128
	AttributePrime                  AttributeType = 0x00000130
	AttributeSubprime               AttributeType = 0x00000131
	AttributeBase                   AttributeType = 0x00000132
	AttributePrimeBits              AttributeType = 0x00000133
	AttributeSubprimeBits           AttributeType = 0x00000134
	AttributeValueBits              AttributeType = 0x00000160
	AttributeValueLen               AttributeType = 0x00000161
	AttributeExtractable            AttributeType = 0x00000162
	AttributeLocal                  AttributeType = 0x00000163
	AttributeNeverExtractable       AttributeType = 0x00000164
	AttributeAlwaysSensitive        AttributeType = 0x00000165
	AttributeKeyGenMechanism        AttributeType = 0x00000166
	AttributeModifiable             AttributeType = 0x00000170
	AttributeCopyable               AttributeType = 0x00000171
	AttributeDestroyable            AttributeType = 0x00000172
	AttributeECDSAParams            AttributeType = 0x00000180
	AttributeECParams               AttributeType = 0x00000180
	AttributeECPoint                AttributeType = 0x00000181
	AttributeSecondaryAuth          AttributeType = 0x00000200
	AttributeAuthPINFlags           AttributeType = 0x00000201
	AttributeAlwaysAuthenticate     AttributeType = 0x00000202
	AttributeWrapWithTrusted        AttributeType = 0x00000210
	AttributeWrapTemplate           AttributeType = 0x40000211
	AttributeUnwrapTemplate         AttributeType = 0x40000212
	AttributeHWFeatureType          AttributeType = 0x00000300
	AttributeResetOnInit            AttributeType = 0x00000301
	AttributeHasReset               AttributeType = 0x00000302
	AttributePixelX                 AttributeType = 0x00000400
	AttributePixelY                 AttributeType = 0x00000401
	AttributeResolution             AttributeType = 0x00000402
	AttributeCharRows               AttributeType = 0x00000403
	AttributeCharColumns            AttributeType = 0x00000404
	AttributeColor                  AttributeType = 0x00000405
	AttributeBitsPerPixel           AttributeType = 0x00000406
	AttributeCharSets               AttributeType = 0x00000480
	AttributeEncodingMethods        AttributeType = 0x00000481
	AttributeMIMETypes              AttributeType = 0x00000482
	AttributeMechanismType          AttributeType = 0x00000500
	AttributeRequiredCMSAttributes  AttributeType = 0x00000501
	AttributeDefaultCMSAttributes   AttributeType = 0x00000502
	AttributeSupportedCMSAttributes AttributeType = 0x00000503
	AttributeAllowedMechanisms      AttributeType = 0x40000600
	AttributeVendorDefined          AttributeType = 0x80000000
)

var attributeString = map[AttributeType]string{
	AttributeClass:                  "CKA_CLASS",
	AttributeToken:                  "CKA_TOKEN",
	AttributePrivate:                "CKA_PRIVATE",
	AttributeLabel:                  "CKA_LABEL",
	AttributeApplication:            "CKA_APPLICATION",
	AttributeValue:                  "CKA_VALUE",
	AttributeObjectID:               "CKA_OBJECT_ID",
	AttributeCertificateType:        "CKA_CERTIFICATE_TYPE",
	AttributeIssuer:                 "CKA_ISSUER",
	AttributeSerialNumber:           "CKA_SERIAL_NUMBER",
	AttributeACIssuer:               "CKA_AC_ISSUER",
	AttributeOwner:                  "CKA_OWNER",
	AttributeAttrTypes:              "CKA_ATTR_TYPES",
	AttributeTrusted:                "CKA_TRUSTED",
	AttributeCertificateCategory:    "CKA_CERTIFICATE_CATEGORY",
	AttributeJavaMIDPSecurityDomain: "CKA_JAVA_MIDP_SECURITY_DOMAIN",
	AttributeURL:                    "CKA_URL",
	AttributeHashOfSubjectPublicKey: "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
	AttributeHashOfIssuerPublicKey:  "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
	AttributeNameHashAlgorithm:      "CKA_NAME_HASH_ALGORITHM",
	AttributeCheckValue:             "CKA_CHECK_VALUE",
	AttributeKeyType:                "CKA_KEY_TYPE",
	AttributeSubject:                "CKA_SUBJECT",
	AttributeID:                     "CKA_ID",
	AttributeSensitive:              "CKA_SENSITIVE",
	AttributeEncrypt:                "CKA_ENCRYPT",
	AttributeDecrypt:                "CKA_DECRYPT",
	AttributeWrap:                   "CKA_WRAP",
	AttributeUnwrap:                 "CKA_UNWRAP",
	AttributeSign:                   "CKA_SIGN",
	AttributeSignRecover:            "CKA_SIGN_RECOVER",
	AttributeVerify:                 "CKA_VERIFY",
	AttributeVerifyRecover:          "CKA_VERIFY_RECOVER",
	AttributeDerive:                 "CKA_DERIVE",
	AttributeStartDate:              "CKA_START_DATE",
	AttributeEndDate:                "CKA_END_DATE",
	AttributeModulus:                "CKA_MODULUS",
	AttributeModulusBits:            "CKA_MODULUS_BITS",
	AttributePublicExponent:         "CKA_PUBLIC_EXPONENT",
	AttributePrivateExponent:        "CKA_PRIVATE_EXPONENT",
	AttributePrime1:                 "CKA_PRIME_1",
	AttributePrime2:                 "CKA_PRIME_2",
	AttributeExponent1:              "CKA_EXPONENT_1",
	AttributeExponent2:              "CKA_EXPONENT_2",
	AttributeCoefficient:            "CKA_COEFFICIENT",
	AttributePrime:                  "CKA_PRIME",
	AttributeSubprime:               "CKA_SUBPRIME",
	AttributeBase:                   "CKA_BASE",
	AttributePrimeBits:              "CKA_PRIME_BITS",
	AttributeSubprimeBits:           "CKA_SUBPRIME_BITS",
	AttributeValueBits:              "CKA_VALUE_BITS",
	AttributeValueLen:               "CKA_VALUE_LEN",
	AttributeExtractable:            "CKA_EXTRACTABLE",
	AttributeLocal:                  "CKA_LOCAL",
	AttributeNeverExtractable:       "CKA_NEVER_EXTRACTABLE",
	AttributeAlwaysSensitive:        "CKA_ALWAYS_SENSITIVE",
	AttributeKeyGenMechanism:        "CKA_KEY_GEN_MECHANISM",
	AttributeModifiable:             "CKA_MODIFIABLE",
	AttributeCopyable:               "CKA_COPYABLE",
	AttributeDestroyable:            "CKA_DESTROYABLE",
	AttributeECDSAParams:            "CKA_ECDSA_PARAMS",
	AttributeECPoint:                "CKA_EC_POINT",
	AttributeSecondaryAuth:          "CKA_SECONDARY_AUTH",
	AttributeAuthPINFlags:           "CKA_AUTH_PIN_FLAGS",
	AttributeAlwaysAuthenticate:     "CKA_ALWAYS_AUTHENTICATE",
	AttributeWrapWithTrusted:        "CKA_WRAP_WITH_TRUSTED",
	AttributeWrapTemplate:           "CKA_WRAP_TEMPLATE",
	AttributeUnwrapTemplate:         "CKA_UNWRAP_TEMPLATE",
	AttributeHWFeatureType:          "CKA_HW_FEATURE_TYPE",
	AttributeResetOnInit:            "CKA_RESET_ON_INIT",
	AttributeHasReset:               "CKA_HAS_RESET",
	AttributePixelX:                 "CKA_PIXEL_X",
	AttributePixelY:                 "CKA_PIXEL_Y",
	AttributeResolution:             "CKA_RESOLUTION",
	AttributeCharRows:               "CKA_CHAR_ROWS",
	AttributeCharColumns:            "CKA_CHAR_COLUMNS",
	AttributeColor:                  "CKA_COLOR",
	AttributeBitsPerPixel:           "CKA_BITS_PER_PIXEL",
	AttributeCharSets:               "CKA_CHAR_SETS",
	AttributeEncodingMethods:        "CKA_ENCODING_METHODS",
	AttributeMIMETypes:              "CKA_MIME_TYPES",
	AttributeMechanismType:          "CKA_MECHANISM_TYPE",
	AttributeRequiredCMSAttributes:  "CKA_REQUIRED_CMS_ATTRIBUTES",
	AttributeDefaultCMSAttributes:   "CKA_DEFAULT_CMS_ATTRIBUTES",
	AttributeSupportedCMSAttributes: "CKA_SUPPORTED_CMS_ATTRIBUTES",
	AttributeAllowedMechanisms:      "CKA_ALLOWED_MECHANISMS",
	AttributeVendorDefined:          "CKA_VENDOR_DEFINED",
}

package p11kit

import (
	"fmt"
	"time"
)

type attribute struct {
	typ   attributeType
	value []byte

	b *byte      // byte
	n *uint64    // ulong
	m []uint64   // mechanism array
	d *time.Time //date
	a []byte     // byte array
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

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L890
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L901
func newByteAttribute(t attributeType, b byte) *attribute {
	return &attribute{typ: t, value: []byte{b}}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L891
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L919
func newUlongAttribute(t attributeType, n uint64) *attribute {
	var b buffer
	b.addUint64(n)
	return &attribute{typ: t, value: b.bytes()}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L893
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L968
func newMechanismTypeArrayAttribute(t attributeType, arr []uint64) *attribute {
	var b buffer
	b.addUint32(uint32(len(arr)))
	for _, m := range arr {
		b.addUint64(m)
	}
	return &attribute{typ: t, value: b.bytes()}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L894
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L998
func newDateAttribute(t attributeType, date time.Time) *attribute {
	var b buffer
	b.addDate(date)
	return &attribute{typ: t, value: b.bytes()}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L895
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L1024
func newByteArrayAttribute(t attributeType, arr []byte) *attribute {
	var b buffer
	b.addByteArray(arr)
	return &attribute{typ: t, value: b.bytes()}
}

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

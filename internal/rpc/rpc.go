// Package rpc implements parsing for the p11-kit RPC protocol.
package rpc

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Call represents a specific PKCS #11 function being called.
type Call uint32

// String returns a human readable name of the Call.
func (c Call) String() string {
	if s, ok := callStrings[c]; ok {
		return s
	}
	return fmt.Sprintf("unknown Call(%d)", uint32(c))
}

var callStrings = map[Call]string{
	CallInitialize:          "C_Initialize",
	CallFinalize:            "C_Finalize",
	CallGetInfo:             "C_GetInfo",
	CallGetSlotList:         "C_GetSlotList",
	CallGetSlotInfo:         "C_GetSlotInfo",
	CallGetTokenInfo:        "C_GetTokenInfo",
	CallGetMechanismList:    "C_GetMechanismList",
	CallGetMechanismInfo:    "C_GetMechanismInfo",
	CallInitToken:           "C_InitToken",
	CallOpenSession:         "C_OpenSession",
	CallCloseSession:        "C_CloseSession",
	CallCloseAllSessions:    "C_CloseAllSessions",
	CallGetSessionInfo:      "C_GetSessionInfo",
	CallInitPIN:             "C_InitPIN",
	CallSetPIN:              "C_SetPIN",
	CallGetOperationState:   "C_GetOperationState",
	CallSetOperationState:   "C_SetOperationState",
	CallLogin:               "C_Login",
	CallLogout:              "C_Logout",
	CallCreateObject:        "C_CreateObject",
	CallCopyObject:          "C_CopyObject",
	CallDestroyObject:       "C_DestroyObject",
	CallGetObjectSize:       "C_GetObjectSize",
	CallGetAttributeValue:   "C_GetAttributeValue",
	CallSetAttributeValue:   "C_SetAttributeValue",
	CallFindObjectsInit:     "C_FindObjectsInit",
	CallFindObjects:         "C_FindObjects",
	CallFindObjectsFinal:    "C_FindObjectsFinal",
	CallEncryptInit:         "C_EncryptInit",
	CallEncrypt:             "C_Encrypt",
	CallEncryptUpdate:       "C_EncryptUpdate",
	CallEncryptFinal:        "C_EncryptFinal",
	CallDecryptInit:         "C_DecryptInit",
	CallDecrypt:             "C_Decrypt",
	CallDecryptUpdate:       "C_DecryptUpdate",
	CallDecryptFinal:        "C_DecryptFinal",
	CallDigestInit:          "C_DigestInit",
	CallDigest:              "C_Digest",
	CallDigestUpdate:        "C_DigestUpdate",
	CallDigestKey:           "C_DigestKey",
	CallDigestFinal:         "C_DigestFinal",
	CallSignInit:            "C_SignInit",
	CallSign:                "C_Sign",
	CallSignUpdate:          "C_SignUpdate",
	CallSignFinal:           "C_SignFinal",
	CallSignRecoverInit:     "C_SignRecoverInit",
	CallSignRecover:         "C_SignRecover",
	CallVerifyInit:          "C_VerifyInit",
	CallVerify:              "C_Verify",
	CallVerifyUpdate:        "C_VerifyUpdate",
	CallVerifyFinal:         "C_VerifyFinal",
	CallVerifyRecoverInit:   "C_VerifyRecoverInit",
	CallVerifyRecover:       "C_VerifyRecover",
	CallDigestEncryptUpdate: "C_DigestEncryptUpdate",
	CallDecryptDigestUpdate: "C_DecryptDigestUpdate",
	CallSignEncryptUpdate:   "C_SignEncryptUpdate",
	CallDecryptVerifyUpdate: "C_DecryptVerifyUpdate",
	CallGenerateKey:         "C_GenerateKey",
	CallGenerateKeyPair:     "C_GenerateKeyPair",
	CallWrapKey:             "C_WrapKey",
	CallUnwrapKey:           "C_UnwrapKey",
	CallDeriveKey:           "C_DeriveKey",
	CallSeedRandom:          "C_SeedRandom",
	CallGenerateRandom:      "C_GenerateRandom",
	CallWaitForSlotEvent:    "C_WaitForSlotEvent",
}

// Call values supported by this package.
//
// See https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.h#L46
const (
	CallError               Call = 0
	CallInitialize               = 1
	CallFinalize                 = 2
	CallGetInfo                  = 3
	CallGetSlotList              = 4
	CallGetSlotInfo              = 5
	CallGetTokenInfo             = 6
	CallGetMechanismList         = 7
	CallGetMechanismInfo         = 8
	CallInitToken                = 9
	CallOpenSession              = 10
	CallCloseSession             = 11
	CallCloseAllSessions         = 12
	CallGetSessionInfo           = 13
	CallInitPIN                  = 14
	CallSetPIN                   = 15
	CallGetOperationState        = 16
	CallSetOperationState        = 17
	CallLogin                    = 18
	CallLogout                   = 19
	CallCreateObject             = 20
	CallCopyObject               = 21
	CallDestroyObject            = 22
	CallGetObjectSize            = 23
	CallGetAttributeValue        = 24
	CallSetAttributeValue        = 25
	CallFindObjectsInit          = 26
	CallFindObjects              = 27
	CallFindObjectsFinal         = 28
	CallEncryptInit              = 29
	CallEncrypt                  = 30
	CallEncryptUpdate            = 31
	CallEncryptFinal             = 32
	CallDecryptInit              = 33
	CallDecrypt                  = 34
	CallDecryptUpdate            = 35
	CallDecryptFinal             = 36
	CallDigestInit               = 37
	CallDigest                   = 38
	CallDigestUpdate             = 39
	CallDigestKey                = 40
	CallDigestFinal              = 41
	CallSignInit                 = 42
	CallSign                     = 43
	CallSignUpdate               = 44
	CallSignFinal                = 45
	CallSignRecoverInit          = 46
	CallSignRecover              = 47
	CallVerifyInit               = 48
	CallVerify                   = 49
	CallVerifyUpdate             = 50
	CallVerifyFinal              = 51
	CallVerifyRecoverInit        = 52
	CallVerifyRecover            = 53
	CallDigestEncryptUpdate      = 54
	CallDecryptDigestUpdate      = 55
	CallSignEncryptUpdate        = 56
	CallDecryptVerifyUpdate      = 57
	CallGenerateKey              = 58
	CallGenerateKeyPair          = 59
	CallWrapKey                  = 60
	CallUnwrapKey                = 61
	CallDeriveKey                = 62
	CallSeedRandom               = 63
	CallGenerateRandom           = 64
	CallWaitForSlotEvent         = 65
)

var binaryEncoding = binary.BigEndian

func parseUint32(b []byte) (uint32, []byte, bool) {
	if len(b) < 4 {
		return 0, nil, false
	}
	n := binaryEncoding.Uint32(b[:4])
	return n, b[4:], true
}

func parseArray(b []byte) (arr, rest []byte, err error) {
	n, b, ok := parseUint32(b)
	if !ok {
		return nil, nil, fmt.Errorf("not enough bytes to read array length")
	}
	if len(b) < int(n) {
		return nil, nil, fmt.Errorf("not enough bytes to read array of length %d", n)
	}
	return b[:int(n)], b[int(n):], nil
}

// A message has the form:
//
//	message_id (uint32)
//	options_lenth (uint32)
//	body_length (uint32)
//	options (array of bytes)
//	body (array of bytes)
//
// A body has the form:
//
//	call_id (uint32)
//	signature_length (uint32)
//	signature (array of bytes)
//	fields (rest of the data)
//

// ReadRequest parses a request from a stream.
func ReadRequest(r io.Reader) (messageID uint32, body *Body, err error) {
	var h header
	if err := binary.Read(r, binaryEncoding, &h); err != nil {
		return 0, nil, fmt.Errorf("reading request header: %v", err)
	}
	optsLen := int(h.OptionsLen)
	buffLen := int(h.BufferLen)
	n := optsLen + buffLen

	// Perform overflow detection.
	if n < 0 || n < optsLen || n-optsLen != buffLen {
		return 0, nil, fmt.Errorf("requested buffer too large")
	}

	// TODO(ericchiang): Do we want to limit the size of the body we can read?
	buff := make([]byte, n)
	if _, err := io.ReadFull(r, buff); err != nil {
		return 0, nil, fmt.Errorf("reading request body: %v", err)
	}

	// We ignore the "options" field since that's what the upstream server does.

	b, err := parseBody(buff[optsLen:])
	if err != nil {
		return 0, nil, fmt.Errorf("parse body: %v", err)
	}
	return h.ID, b, nil
}

// WriteResponse encodes a body to the writer.
func WriteResponse(w io.Writer, messageID uint32, body *Body) error {
	nb := body.encodingLength()
	// Header + body, no options.
	n := 12 + nb
	buff := make([]byte, n)

	// Write header.
	binaryEncoding.PutUint32(buff[:4], messageID)
	// OptionsLength is zero, keep the zero value.
	binaryEncoding.PutUint32(buff[8:12], uint32(nb))

	body.encodeTo(buff[12:])

	_, err := w.Write(buff)
	return err
}

type header struct {
	ID         uint32
	OptionsLen uint32
	BufferLen  uint32
}

// Body can be used to either parse a request or build a response.
type Body struct {
	Call Call

	signature string
	bytes     []byte
}

func (b *Body) encodeTo(buf []byte) {
	ns := len(b.signature)

	binaryEncoding.PutUint32(buf[:4], uint32(b.Call))
	binaryEncoding.PutUint32(buf[4:8], uint32(ns))
	copy(buf[8:], []byte(b.signature))
	copy(buf[8+ns:], b.bytes)
}

func (b *Body) encodingLength() int {
	return 4 + 4 + len(b.signature) + len(b.bytes)
}

func parseBody(b []byte) (*Body, error) {
	call, b, ok := parseUint32(b)
	if !ok {
		return nil, fmt.Errorf("not enought bytes to read call ID")
	}
	sigBytes, bytes, err := parseArray(b)
	if err != nil {
		return nil, fmt.Errorf("parsing signature: %v", err)
	}
	return &Body{
		Call:      Call(call),
		signature: string(sigBytes),
		bytes:     bytes,
	}, nil
}

const (
	sigByte      = "y"
	sigByteArray = "ay"
	sigLong      = "u"
	sigLongArray = "au"
	sigLongBuff  = "fu"
	sigString    = "s"
	sigVersion   = "v"
)

func (b *Body) nextSig(want string) error {
	if !strings.HasPrefix(b.signature, want) {
		return fmt.Errorf("invalid signature attempting to parse '%s' from '%s'", want, b.signature)
	}
	b.signature = strings.TrimPrefix(b.signature, want)
	return nil
}

func (b *Body) readByte() (byte, bool) {
	if len(b.bytes) < 1 {
		return 0, false
	}
	y := b.bytes[0]
	b.bytes = b.bytes[1:]
	return y, true
}

// Close checks to ensure a body has been fully consumed.
func (b *Body) Close() error {
	if len(b.signature) != 0 {
		return fmt.Errorf("trailing fields in body: %s", b.signature)
	}
	if len(b.bytes) != 0 {
		return fmt.Errorf("trailing bytes in body: %d", len(b.bytes))
	}
	return nil
}

// Byte parses a single byte ('y') from a request.
func (b *Body) Byte() (byte, error) {
	if err := b.nextSig(sigByte); err != nil {
		return 0, err
	}
	if n, ok := b.readByte(); ok {
		return n, nil
	}
	return 0, fmt.Errorf("unexpected EOF reading byte")
}

// Buffer parses a buffer length ('fu') from a request. While p11-kit will
// allocate the buffer,
//
// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-server.c#L172
func (b *Body) Buffer() (uint32, error) {
	if err := b.nextSig(sigLongBuff); err != nil {
		return 0, err
	}
	return b.uint32()
}

// Bytes parses a byte array ('ay') from a request. The byte array must have
// content.
func (b *Body) Bytes() ([]byte, error) {
	_, bytes, err := b.BytesOrLength()
	if err != nil {
		return nil, err
	}
	if bytes == nil {
		return nil, fmt.Errorf("byte array has no content")
	}
	return bytes, nil
}

// BytesLength parses a byte array ('ay') from a request, and returns its length.
// The byte array may or may not have content.
func (b *Body) BytesLength() (uint32, error) {
	n, _, err := b.BytesOrLength()
	return n, err
}

// BytesOrLength parses a byte array ('ay') from a request. It may or may not
// contain content. If not, the returned array will be nil.
func (b *Body) BytesOrLength() (uint32, []byte, error) {
	if len(b.bytes) == 0 {
		return 0, nil, fmt.Errorf("unexpected eof parsing byte array")
	}
	hasBody := b.bytes[0] == 1
	b.bytes = b.bytes[1:]

	if err := b.nextSig(sigByteArray); err != nil {
		return 0, nil, err
	}

	if !hasBody {
		n, err := b.uint32()
		return n, nil, err
	}

	arr, rest, err := parseArray(b.bytes)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing byte array: %v", err)
	}
	b.bytes = rest
	return uint32(len(arr)), arr, nil
}

// Ulong parses a uint64 from the body.
func (b *Body) Ulong() (uint64, error) {
	if err := b.nextSig(sigLong); err != nil {
		return 0, err
	}
	return b.uint64()
}

func (b *Body) uint32() (uint32, error) {
	n, rest, ok := parseUint32(b.bytes)
	if !ok {
		return 0, fmt.Errorf("unexpected eof parsing byte array length")
	}
	b.bytes = rest
	return n, nil
}

func (b *Body) uint64() (uint64, error) {
	if len(b.bytes) < 8 {
		return 0, fmt.Errorf("unexpected eof parsing uint64")
	}
	n := binaryEncoding.Uint64(b.bytes[:8])
	b.bytes = b.bytes[8:]
	return n, nil
}

func (b *Body) appendSignature(s string) {
	b.signature = b.signature + s
}

func (b *Body) appendUint32(n uint32) {
	var buff [4]byte
	binaryEncoding.PutUint32(buff[:], n)
	b.bytes = append(b.bytes, buff[:]...)
}

func (b *Body) appendUint64(n uint64) {
	var buff [8]byte
	binaryEncoding.PutUint64(buff[:], n)
	b.bytes = append(b.bytes, buff[:]...)

}

// AppendUlong adds a uint64 object to the body.
func (b *Body) AppendUlong(n uint64) {
	b.appendUint64(n)
	b.appendSignature(sigLong)
}

// AppendByte adds a byte object to the body.
func (b *Body) AppendByte(c byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L313
	b.bytes = append(b.bytes, c)
	b.signature = b.signature + sigByte
}

// AppendBytes adds a byte array object to the body.
func (b *Body) AppendBytes(arr []byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L371
	b.bytes = append(b.bytes, 1) // Array has content.
	b.appendUint32(uint32(len(arr)))
	b.bytes = append(b.bytes, arr...)
	b.signature = b.signature + sigByteArray
}

// AppendBytesLength appends the length of a byte array, without writing its
// content.
func (b *Body) AppendBytesLength(n int) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L371
	b.bytes = append(b.bytes, 0) // Array has no content.
	b.appendUint32(uint32(n))
	b.signature = b.signature + sigByteArray
}

// AppendUlongs adds an array of uint64s to the body.
func (b *Body) AppendUlongs(arr []uint64) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L407
	b.bytes = append(b.bytes, 1) // has content
	b.appendUint32(uint32(len(arr)))
	for _, v := range arr {
		b.appendUint64(v)
	}
	b.appendSignature(sigLongArray)
}

// AppendUint64s adds the length of a uint64 array to the body.
func (b *Body) AppendUlongsLength(n int) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L407
	b.bytes = append(b.bytes, 0) // has no content
	b.appendUint32(uint32(n))
	b.appendSignature(sigLongArray)
}

// AppendVersion adds a version object to the body.
func (b *Body) AppendVersion(major, minor byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L448
	b.bytes = append(b.bytes, major, minor)
	b.signature = b.signature + sigVersion
}

// AppendString adds a space-padded string to the body. The maxLength argument
// declares the pre-agreed size of the string for the PKCS #11 spec, and the
// input string is padded with spaces until it reaches that length.
//
// If the input string is longer than maxLength, only maxLength bytes will be
// added to the body.
func (b *Body) AppendString(s string, maxLength int) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L493
	buf := make([]byte, maxLength)
	for i := 0; i < maxLength; i++ {
		if i < len(s) {
			buf[i] = s[i]
		} else {
			buf[i] = ' '
		}
	}
	var sLen [4]byte
	binaryEncoding.PutUint32(sLen[:], uint32(maxLength))

	b.bytes = append(b.bytes, sLen[:]...)
	b.bytes = append(b.bytes, buf...)
	b.signature = b.signature + sigString
}

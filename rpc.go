package p11kit

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type call uint32

func (c call) String() string {
	if s, ok := callStrings[c]; ok {
		return s
	}
	return fmt.Sprintf("unknown call(%d)", uint32(c))
}

var callStrings = map[call]string{
	callInitialize:          "C_Initialize",
	callFinalize:            "C_Finalize",
	callGetInfo:             "C_GetInfo",
	callGetSlotList:         "C_GetSlotList",
	callGetSlotInfo:         "C_GetSlotInfo",
	callGetTokenInfo:        "C_GetTokenInfo",
	callGetMechanismList:    "C_GetMechanismList",
	callGetMechanismInfo:    "C_GetMechanismInfo",
	callInitToken:           "C_InitToken",
	callOpenSession:         "C_OpenSession",
	callCloseSession:        "C_CloseSession",
	callCloseAllSessions:    "C_CloseAllSessions",
	callGetSessionInfo:      "C_GetSessionInfo",
	callInitPIN:             "C_InitPIN",
	callSetPIN:              "C_SetPIN",
	callGetOperationState:   "C_GetOperationState",
	callSetOperationState:   "C_SetOperationState",
	callLogin:               "C_Login",
	callLogout:              "C_Logout",
	callCreateObject:        "C_CreateObject",
	callCopyObject:          "C_CopyObject",
	callDestroyObject:       "C_DestroyObject",
	callGetObjectSize:       "C_GetObjectSize",
	callGetAttributeValue:   "C_GetAttributeValue",
	callSetAttributeValue:   "C_SetAttributeValue",
	callFindObjectsInit:     "C_FindObjectsInit",
	callFindObjects:         "C_FindObjects",
	callFindObjectsFinal:    "C_FindObjectsFinal",
	callEncryptInit:         "C_EncryptInit",
	callEncrypt:             "C_Encrypt",
	callEncryptUpdate:       "C_EncryptUpdate",
	callEncryptFinal:        "C_EncryptFinal",
	callDecryptInit:         "C_DecryptInit",
	callDecrypt:             "C_Decrypt",
	callDecryptUpdate:       "C_DecryptUpdate",
	callDecryptFinal:        "C_DecryptFinal",
	callDigestInit:          "C_DigestInit",
	callDigest:              "C_Digest",
	callDigestUpdate:        "C_DigestUpdate",
	callDigestKey:           "C_DigestKey",
	callDigestFinal:         "C_DigestFinal",
	callSignInit:            "C_SignInit",
	callSign:                "C_Sign",
	callSignUpdate:          "C_SignUpdate",
	callSignFinal:           "C_SignFinal",
	callSignRecoverInit:     "C_SignRecoverInit",
	callSignRecover:         "C_SignRecover",
	callVerifyInit:          "C_VerifyInit",
	callVerify:              "C_Verify",
	callVerifyUpdate:        "C_VerifyUpdate",
	callVerifyFinal:         "C_VerifyFinal",
	callVerifyRecoverInit:   "C_VerifyRecoverInit",
	callVerifyRecover:       "C_VerifyRecover",
	callDigestEncryptUpdate: "C_DigestEncryptUpdate",
	callDecryptDigestUpdate: "C_DecryptDigestUpdate",
	callSignEncryptUpdate:   "C_SignEncryptUpdate",
	callDecryptVerifyUpdate: "C_DecryptVerifyUpdate",
	callGenerateKey:         "C_GenerateKey",
	callGenerateKeyPair:     "C_GenerateKeyPair",
	callWrapKey:             "C_WrapKey",
	callUnwrapKey:           "C_UnwrapKey",
	callDeriveKey:           "C_DeriveKey",
	callSeedRandom:          "C_SeedRandom",
	callGenerateRandom:      "C_GenerateRandom",
	callWaitForSlotEvent:    "C_WaitForSlotEvent",
}

// call values supported by this package.
//
// See https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.h#L46
const (
	callError               call = 0
	callInitialize               = 1
	callFinalize                 = 2
	callGetInfo                  = 3
	callGetSlotList              = 4
	callGetSlotInfo              = 5
	callGetTokenInfo             = 6
	callGetMechanismList         = 7
	callGetMechanismInfo         = 8
	callInitToken                = 9
	callOpenSession              = 10
	callCloseSession             = 11
	callCloseAllSessions         = 12
	callGetSessionInfo           = 13
	callInitPIN                  = 14
	callSetPIN                   = 15
	callGetOperationState        = 16
	callSetOperationState        = 17
	callLogin                    = 18
	callLogout                   = 19
	callCreateObject             = 20
	callCopyObject               = 21
	callDestroyObject            = 22
	callGetObjectSize            = 23
	callGetAttributeValue        = 24
	callSetAttributeValue        = 25
	callFindObjectsInit          = 26
	callFindObjects              = 27
	callFindObjectsFinal         = 28
	callEncryptInit              = 29
	callEncrypt                  = 30
	callEncryptUpdate            = 31
	callEncryptFinal             = 32
	callDecryptInit              = 33
	callDecrypt                  = 34
	callDecryptUpdate            = 35
	callDecryptFinal             = 36
	callDigestInit               = 37
	callDigest                   = 38
	callDigestUpdate             = 39
	callDigestKey                = 40
	callDigestFinal              = 41
	callSignInit                 = 42
	callSign                     = 43
	callSignUpdate               = 44
	callSignFinal                = 45
	callSignRecoverInit          = 46
	callSignRecover              = 47
	callVerifyInit               = 48
	callVerify                   = 49
	callVerifyUpdate             = 50
	callVerifyFinal              = 51
	callVerifyRecoverInit        = 52
	callVerifyRecover            = 53
	callDigestEncryptUpdate      = 54
	callDecryptDigestUpdate      = 55
	callSignEncryptUpdate        = 56
	callDecryptVerifyUpdate      = 57
	callGenerateKey              = 58
	callGenerateKeyPair          = 59
	callWrapKey                  = 60
	callUnwrapKey                = 61
	callDeriveKey                = 62
	callSeedRandom               = 63
	callGenerateRandom           = 64
	callWaitForSlotEvent         = 65
)

var binaryEncoding = binary.BigEndian

type buffer struct {
	b []byte
}

func (b *buffer) Write(buff []byte) (int, error) {
	b.b = append(b.b, buff...)
	return len(buff), nil
}

func (b *buffer) len() int {
	return len(b.b)
}

func (b *buffer) bytes() []byte {
	return b.b
}

func newBuffer(b []byte) buffer {
	return buffer{b: b}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L1039
func (b *buffer) addAttribute(a attribute) {
	panic("TODO")
}

func (b *buffer) addByteArray(a []byte) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L730
	b.addUint32(uint32(len(a)))
	b.b = append(b.b, a...)
}

func (b *buffer) addUint32(n uint32) {
	var buff [4]byte
	binaryEncoding.PutUint32(buff[:], n)
	b.b = append(b.b, buff[:]...)
}

func (b *buffer) addUint64(n uint64) {
	var buff [8]byte
	binaryEncoding.PutUint64(buff[:], n)
	b.b = append(b.b, buff[:]...)
}

func (b *buffer) addByte(by byte) {
	b.b = append(b.b, by)
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L998
func (b *buffer) addDate(t time.Time) {
	year := uint64(t.Year())
	month := uint64(t.Month())
	day := uint64(t.Day())

	if 1000 <= year && year <= 9999 {
		b.b = strconv.AppendUint(b.b, year, 10)
	} else {
		b.b = append(b.b, '0', '0', '0', '0')
	}

	if 0 <= month && month <= 9 {
		b.b = append(b.b, '0')
		b.b = strconv.AppendUint(b.b, month, 10)
	} else if 10 <= month && month <= 99 {
		b.b = strconv.AppendUint(b.b, month, 10)
	} else {
		b.b = append(b.b, '0', '0')
	}

	if 0 <= day && day <= 9 {
		b.b = append(b.b, '0')
		b.b = strconv.AppendUint(b.b, day, 10)
	} else if 10 <= day && day <= 99 {
		b.b = strconv.AppendUint(b.b, day, 10)
	} else {
		b.b = append(b.b, '0', '0')
	}
}

func (b *buffer) byte(by *byte) bool {
	if len(b.b) == 0 {
		return false
	}
	*by = b.b[0]
	b.b = b.b[1:]
	return true
}

func (b *buffer) uint32(n *uint32) bool {
	if len(b.b) < 4 {
		return false
	}
	buff := b.b[:4]
	b.b = b.b[4:]
	*n = binaryEncoding.Uint32(buff)
	return true
}

func (b *buffer) uint64(n *uint64) bool {
	if len(b.b) < 8 {
		return false
	}
	buff := b.b[:8]
	b.b = b.b[8:]
	*n = binaryEncoding.Uint64(buff)
	return true
}

func (b *buffer) byteArray(a *[]byte) bool {
	var n uint32
	if !b.uint32(&n) {
		return false
	}
	if len(b.b) < int(n) {
		return false
	}
	*a = b.b[:n]
	b.b = b.b[n:]
	return true
}

func (b *buffer) date(t *time.Time) bool {
	if len(b.b) < 8 {
		return false
	}
	year, err := strconv.ParseUint(string(b.b[:4]), 10, 64)
	if err != nil {
		return false
	}
	month, err := strconv.ParseUint(string(b.b[4:6]), 10, 64)
	if err != nil {
		return false
	}
	day, err := strconv.ParseUint(string(b.b[6:8]), 10, 64)
	if err != nil {
		return false
	}
	*t = time.Date(int(year), time.Month(month), int(day), 0, 0, 0, 0, time.UTC)
	b.b = b.b[8:]
	return true
}

type body struct {
	call      call
	signature string
	buffer    buffer
	error     error
}

func newResponse(req *body) *body {
	return &body{call: req.call}
}

const (
	sigByte        = "y"
	sigByteArray   = "ay"
	sigUlong       = "u"
	sigUlongArray  = "au"
	sigUlongBuffer = "fu"
	sigString      = "s"
	sigVersion     = "v"
)

func (b *body) err() error {
	if b.error != nil {
		return b.error
	}
	if len(b.signature) != 0 {
		return fmt.Errorf("trailing elements: %s", b.signature)
	}
	if b.buffer.len() != 0 {
		return fmt.Errorf("trailing data: %d bytes", b.buffer.len())
	}
	return nil
}

func (b *body) writeSig(next string) {
	b.signature += next
}

func (b *body) sig(want string) bool {
	if b.error != nil {
		return false
	}
	if !strings.HasPrefix(b.signature, want) {
		b.error = fmt.Errorf("invalid signature attempting to parse '%s' from '%s'", want, b.signature)
		return false
	}
	b.signature = strings.TrimPrefix(b.signature, want)
	return true
}

func (b *body) decode(sig string, fn func() bool) {
	if b.error != nil {
		return
	}
	if !b.sig(sig) {
		return
	}
	if fn() {
		return
	}
	b.error = io.ErrUnexpectedEOF
	return
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L313
func (b *body) writeByte(c byte) {
	b.writeSig(sigByte)
	b.buffer.addByte(c)
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L371
func (b *body) writeByteArray(a []byte, n uint32) {
	b.writeSig(sigByteArray)
	if a == nil {
		b.buffer.addByte(0)
		b.buffer.addUint32(n)
	} else {
		b.buffer.addByte(1)
		b.buffer.addByteArray(a)
	}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L345
func (b *body) writeUlong(n uint64) {
	b.writeSig(sigUlong)
	b.buffer.addUint64(n)
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L407
func (b *body) writeUlongArray(a []uint64, n uint32) {
	b.writeSig(sigUlongArray)
	if a == nil {
		b.buffer.addByte(0)
		b.buffer.addUint32(n)
		return
	}
	b.buffer.addByte(1)
	b.buffer.addUint32(uint32(len(a)))
	for _, ele := range a {
		b.buffer.addUint64(ele)
	}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L493
func (b *body) writeString(s string, n uint32) {
	b.writeSig(sigString)
	b.buffer.addUint32(n)
	for i := 0; i < int(n); i++ {
		if i < len(s) {
			b.buffer.addByte(s[i])
		} else {
			b.buffer.addByte(' ')
		}
	}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L448
func (b *body) writeVersion(v Version) {
	b.writeSig(sigVersion)
	b.buffer.addByte(v.Major)
	b.buffer.addByte(v.Minor)
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L345
func (b *body) readByte(c *byte) {
	b.decode(sigByte, func() bool {
		return b.buffer.byte(c)
	})
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L371
func (b *body) readByteArray(a *[]byte, n *uint32) {
	var (
		arr    []byte
		arrLen uint32
	)
	b.decode(sigByteArray, func() bool {
		var hasContent byte
		if !b.buffer.byte(&hasContent) {
			return false
		}
		if hasContent != 0 {
			return b.buffer.byteArray(&arr)
		}
		return b.buffer.uint32(&arrLen)
	})
	if b.error != nil {
		return
	}
	if a != nil {
		*a = arr
	}
	if n != nil {
		*n = arrLen
	}
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L345
func (b *body) readUlong(n *uint64) {
	b.decode(sigUlong, func() bool {
		return b.buffer.uint64(n)
	})
}

// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.c#L371
func (b *body) readUlongBuffer(count *uint32) {
	b.decode(sigUlongBuffer, func() bool {
		return b.buffer.uint32(count)
	})
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

type header struct {
	ID         uint32
	OptionsLen uint32
	BufferLen  uint32
}

func readRequest(r io.Reader) (uint32, *body, error) {
	var h header
	if err := binary.Read(r, binaryEncoding, &h); err != nil {
		return 0, nil, fmt.Errorf("reading request header: %v", err)
	}
	optsLen := int(h.OptionsLen)
	buffLen := int(h.BufferLen)
	n := optsLen + buffLen

	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, fmt.Errorf("reading request body: %v", err)
	}

	// We ignore the "options" field since that's what the upstream server does.

	buff := newBuffer(b[optsLen:])
	var (
		callID   uint32
		sigBytes []byte
	)
	if !buff.uint32(&callID) || !buff.byteArray(&sigBytes) {
		return 0, nil, fmt.Errorf("malformed request body")
	}
	return h.ID, &body{call: call(callID), signature: string(sigBytes), buffer: buff}, nil
}

func writeResponse(w io.Writer, messageID uint32, body *body) error {
	bodyLen := 4 + 4 + len(body.signature) + body.buffer.len()

	var b buffer
	b.addUint32(messageID)
	b.addUint32(0) // options lengh is zero.
	b.addUint32(uint32(bodyLen))

	b.addUint32(uint32(body.call))
	b.addByteArray([]byte(body.signature))
	b.Write(body.buffer.bytes())
	_, err := w.Write(b.bytes())
	return err
}

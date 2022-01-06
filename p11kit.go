// Package p11kit implements the p11-kit RPC protocol.
package p11kit

import (
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/p11kit/internal/rpc"
)

// Error represents a PKCS #11 return code.
type Error uint64

var errStrings = map[Error]string{
	ErrSlotIDInvalid: "invalid slot ID",
	ErrGeneralError:  "general error",
	ErrArgumentsBad:  "invalid function arguments",
}

// Error returns a human readable message of the PKCS #11 return code.
func (e Error) Error() string {
	if s, ok := errStrings[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown pkcs11 error: 0x%08x", uint64(e))
}

// Error codes defined PKCS #11.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/csd02/pkcs11-base-v2.40-csd02.html#_Toc385435538
const (
	ErrCancel                        Error = 0x00000001
	ErrHostMemory                    Error = 0x00000002
	ErrSlotIDInvalid                 Error = 0x00000003
	ErrGeneralError                  Error = 0x00000005
	ErrFunctionFailed                Error = 0x00000006
	ErrArgumentsBad                  Error = 0x00000007
	ErrNoEvent                       Error = 0x00000008
	ErrNeedToCreateThreads           Error = 0x00000009
	ErrCantLock                      Error = 0x0000000a
	ErrAttributeReadOnly             Error = 0x00000010
	ErrAttributeSensitive            Error = 0x00000011
	ErrAttributeTypeInvalid          Error = 0x00000012
	ErrAttributeValueInvalid         Error = 0x00000013
	ErrCopyProhibited                Error = 0x0000001a
	ErrActionProhibited              Error = 0x0000001b
	ErrDataInvalid                   Error = 0x00000020
	ErrDataLenRange                  Error = 0x00000021
	ErrDeviceError                   Error = 0x00000030
	ErrDeviceMemory                  Error = 0x00000031
	ErrDeviceRemoved                 Error = 0x00000032
	ErrEncryptedDataInvalid          Error = 0x00000040
	ErrEncryptedDataLenRange         Error = 0x00000041
	ErrFunctionCanceled              Error = 0x00000050
	ErrFunctionNotParallel           Error = 0x00000051
	ErrFunctionNotSupported          Error = 0x00000054
	ErrKeyHandleInvalid              Error = 0x00000060
	ErrKeySizeRange                  Error = 0x00000062
	ErrKeyTypeInconsistent           Error = 0x00000063
	ErrKeyNotNeeded                  Error = 0x00000064
	ErrKeyChanged                    Error = 0x00000065
	ErrKeyNeeded                     Error = 0x00000066
	ErrKeyIndigestible               Error = 0x00000067
	ErrKeyFunctionNotPermitted       Error = 0x00000068
	ErrKeyNotWrappable               Error = 0x00000069
	ErrKeyUnextractable              Error = 0x0000006a
	ErrMechanismInvalid              Error = 0x00000070
	ErrMechanismParamInvalid         Error = 0x00000071
	ErrObjectHandleInvalid           Error = 0x00000082
	ErrOperationActive               Error = 0x00000090
	ErrOperationNotInitialized       Error = 0x00000091
	ErrPINIncorrect                  Error = 0x000000a0
	ErrPINInvalid                    Error = 0x000000a1
	ErrPINLenRange                   Error = 0x000000a2
	ErrPINExpired                    Error = 0x000000a3
	ErrPINLocked                     Error = 0x000000a4
	ErrSessionClosed                 Error = 0x000000b0
	ErrSessionCount                  Error = 0x000000b1
	ErrSessionHandleInvalid          Error = 0x000000b3
	ErrSessionParallelNotSupported   Error = 0x000000b4
	ErrSessionReadOnly               Error = 0x000000b5
	ErrSessionExists                 Error = 0x000000b6
	ErrSessionReadOnlyExists         Error = 0x000000b7
	ErrSessionReadWriteSoExists      Error = 0x000000b8
	ErrSignatureInvalid              Error = 0x000000c0
	ErrSignatureLenRange             Error = 0x000000c1
	ErrTemplateIncomplete            Error = 0x000000d0
	ErrTemplateInconsistent          Error = 0x000000d1
	ErrTokenNotPresent               Error = 0x000000e0
	ErrTokenNotRecognized            Error = 0x000000e1
	ErrTokenWriteProtected           Error = 0x000000e2
	ErrUnwrappingKeyHandleInvalid    Error = 0x000000f0
	ErrUnwrappingKeySizeRange        Error = 0x000000f1
	ErrUnwrappingKeyTypeInconsistent Error = 0x000000f2
	ErrUserAlreadyLoggedIn           Error = 0x00000100
	ErrUserNotLoggedIn               Error = 0x00000101
	ErrUserPINNotInitialized         Error = 0x00000102
	ErrUserTypeInvalid               Error = 0x00000103
	ErrUserAnotherAlreadyLoggedIn    Error = 0x00000104
	ErrUserTooManyTypes              Error = 0x00000105
	ErrWrappedKeyInvalid             Error = 0x00000110
	ErrWrappedKeyLenRange            Error = 0x00000112
	ErrWrappingKeyHandleInvalid      Error = 0x00000113
	ErrWrappingKeySizeRange          Error = 0x00000114
	ErrWrappingKeyTypeInconsistent   Error = 0x00000115
	ErrRandomSeedNotSupported        Error = 0x00000120
	ErrRandomNoRNG                   Error = 0x00000121
	ErrDomainParamsInvalid           Error = 0x00000130
	ErrCurveNotSupported             Error = 0x00000140
	ErrBufferTooSmall                Error = 0x00000150
	ErrSavedStateInvalid             Error = 0x00000160
	ErrInformationSensitive          Error = 0x00000170
	ErrStateUnsaveable               Error = 0x00000180
	ErrCryptokiNotInitialized        Error = 0x00000190
	ErrCryptokiAlreadyInitialized    Error = 0x00000191
	ErrMutexBad                      Error = 0x000001a0
	ErrMutexNotLocked                Error = 0x000001a1
	ErrFunctionRejected              Error = 0x00000200
	ErrVendorDefined                 Error = 0x80000000
)

// Special PKCS #11 values that can be used instead of certain flags.
const (
	EffectivelyInfinite    = 0x0
	UnavailableInformation = math.MaxUint64
)

// InitializeArgs holds CK_C_INITIALIZE_ARGS fields.
type InitializeArgs struct {
}

// Version holds a major and minor version number, used in various fields in
// the PKCS #11 interface.
//
// This corresponds to CK_VERSION.
type Version struct {
	Major byte
	Minor byte
}

// Info holds general information about the PKCS #11 module.
//
// This corresponds to CK_INFO.
type Info struct {
	CryptokiVersion Version
	Manufacturer    string // Limit of 32 bytes
	Library         string // Limit of 32 bytes
	LibraryVersion  Version

	// Flags is ignored since "bit flags reserved for future versions.  MUST be zero for this version"
}

// SessionID corresponds to CK_SESSION_HANDLE.
type SessionID uint64

// SlotID corresponds to CK_SLOT_ID.
type SlotID uint64

const (
	slotInfoFlagTokenPresent    = 0x00000001
	slotInfoFlagRemovableDevice = 0x00000002
	slotInfoFlagHWSlot          = 0x00000004
)

// SlotInfo holds information about a slot, a grouping of objects such as
// certificates, public keys, and private keys.
//
//// This corresponds to CK_SLOT_INFO.
type SlotInfo struct {
	Description    string // Limit of 64 bytes
	ManufacturerID string // Limit of 32 bytes

	// TODO(ericchiang): encode these values in flags.

	TokenPresent    bool
	RemovableDevice bool
	HardwareSlot    bool

	HardwareVersion Version
	FirmwareVersion Version
}

// TokenInfo holds information about a token, the entity that "backs" the slot.
//
// Practically, there's very little difference between a token and a slot, and
// treating these as a single component is valid.
//
// This corresponds to CK_TOKEN_INFO.
type TokenInfo struct {
	Label          string // Limit of 32 bytes
	ManufacturerID string // Limit of 32 bytes
	Model          string // Limit of 16 bytes
	SerialNumber   string // Limit of 16 bytes

	Flags uint64

	// TODO(ericchiang): Default counts to reasonable values.

	MaxSessionCount   uint64
	SessionCount      uint64
	MaxRWSessionCount uint64
	RWSessionCount    uint64

	MaxPINLen uint64
	MinPINLen uint64

	TotalPublicMemory  uint64
	FreePublicMemory   uint64
	TotalPrivateMemory uint64
	FreePrivateMemory  uint64

	HardwareVersion Version
	FirmwareVersion Version

	// TODO(ericchiang): Default to time.Now().
	Time time.Time
}

// Server implements a server for the p11-kit PRC protocol.
type Server struct {
	// General purpose APIs.
	//
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959740
	Initialize func(args *InitializeArgs) error
	GetInfo    func() (*Info, error)

	// Slot and token management APIs.
	//
	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959741
	GetSlotList  func(tokenPresnt bool) ([]SlotID, error)
	GetSlotInfo  func(id SlotID) (*SlotInfo, error)
	GetTokenInfo func(id SlotID) (*TokenInfo, error)

	OpenSession  func(id SlotID, flags uint64) (SessionID, error)
	CloseSession func(id SessionID) error
}

// Handle begins serving RPC requests. p11-kit sessions are per-connection, not
// concurrent. The client will open a single connection, call Initialize() and
// issue comments, then Finalize() and drop the connection.
//
// Once this method returns, any resources associated with Server can be
// released.
func (s *Server) Handle(rw io.ReadWriter) error {
	if err := negotiateProtocolVersion(rw); err != nil {
		return fmt.Errorf("negotiating protocol version: %v", err)
	}

	done := false
	handlers := map[rpc.Call]func(*rpc.Body) (*rpc.Body, error){
		rpc.CallFinalize: func(req *rpc.Body) (*rpc.Body, error) {
			done = true
			return req, nil
		},
		rpc.CallInitialize:   s.handleInitialize,
		rpc.CallGetInfo:      s.handleGetInfo,
		rpc.CallGetSlotList:  s.handleGetSlotList,
		rpc.CallGetTokenInfo: s.handleGetTokenInfo,
		rpc.CallGetSlotInfo:  s.handleGetSlotInfo,
		rpc.CallOpenSession:  s.handleOpenSession,
		rpc.CallCloseSession: s.handleCloseSession,
	}

	for !done {
		callID, req, err := rpc.ReadRequest(rw)
		if err != nil {
			return fmt.Errorf("read request: %v", err)
		}
		var resp *rpc.Body
		if h, ok := handlers[req.Call]; ok {
			resp, err = h(req)
		} else {
			err = ErrFunctionNotSupported
		}
		if err != nil {
			var cerr Error
			if !errors.As(err, &cerr) {
				return fmt.Errorf("%s failed: %v", req.Call, err)
			}

			// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L142-L143
			resp = &rpc.Body{Call: rpc.CallError}
			resp.AppendUlong(uint64(cerr))
		}
		if err := rpc.WriteResponse(rw, callID, resp); err != nil {
			return fmt.Errorf("writing response: %v", err)
		}
	}
	return nil
}

func (s *Server) handleInitialize(req *rpc.Body) (*rpc.Body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.h#L215
	const handshakeMessage = "PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1"

	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L774-L792

	handshake, err := req.Bytes()
	if err != nil {
		return nil, fmt.Errorf("read handshake: %v", err)
	}
	if _, err := req.Byte(); err != nil {
		return nil, fmt.Errorf("read reserved byte: %v", err)
	}
	if _, _, err := req.BytesOrLength(); err != nil {
		return nil, fmt.Errorf("read reserved data: %v", err)
	}
	if err := req.Close(); err != nil {
		return nil, fmt.Errorf("processing request: %v", err)
	}
	if string(handshake) != handshakeMessage {
		return nil, fmt.Errorf("client sent unexpected handshake message: %s", handshake)
	}
	if s.Initialize == nil {
		return nil, ErrFunctionNotSupported
	}
	if err := s.Initialize(&InitializeArgs{}); err != nil {
		return nil, fmt.Errorf("initializing module: %w", err)
	}
	return &rpc.Body{Call: req.Call}, nil
}

func (s *Server) handleGetInfo(req *rpc.Body) (*rpc.Body, error) {
	if err := req.Close(); err != nil {
		return nil, fmt.Errorf("processing request: %v", err)
	}
	if s.GetInfo == nil {
		return nil, ErrFunctionNotSupported
	}
	info, err := s.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("get module info: %w", err)
	}
	resp := &rpc.Body{Call: rpc.CallGetInfo}
	resp.AppendVersion(info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	resp.AppendString(info.Manufacturer, 32)
	resp.AppendUlong(0) // Flags is always zero.
	resp.AppendString(info.Library, 32)
	resp.AppendVersion(info.LibraryVersion.Major, info.LibraryVersion.Minor)
	return resp, nil
}

func (s *Server) handleGetTokenInfo(req *rpc.Body) (*rpc.Body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L905
	slotID, err := req.Ulong()
	if err != nil {
		return nil, fmt.Errorf("reading slot ID")
	}
	if err := req.Close(); err != nil {
		return nil, err
	}
	if s.GetTokenInfo == nil {
		return nil, ErrFunctionNotSupported
	}
	info, err := s.GetTokenInfo(SlotID(slotID))
	if err != nil {
		return nil, err
	}

	resp := &rpc.Body{Call: rpc.CallGetTokenInfo}
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L484
	resp.AppendString(info.Label, 32)
	resp.AppendString(info.ManufacturerID, 32)

	resp.AppendString(info.Model, 16)
	resp.AppendString(info.SerialNumber, 16)

	resp.AppendUlong(info.Flags)

	resp.AppendUlong(info.MaxSessionCount)
	resp.AppendUlong(info.SessionCount)
	resp.AppendUlong(info.MaxRWSessionCount)
	resp.AppendUlong(info.RWSessionCount)

	resp.AppendUlong(info.MaxPINLen)
	resp.AppendUlong(info.MinPINLen)

	resp.AppendUlong(info.TotalPublicMemory)
	resp.AppendUlong(info.FreePublicMemory)
	resp.AppendUlong(info.TotalPrivateMemory)
	resp.AppendUlong(info.FreePrivateMemory)

	resp.AppendVersion(info.HardwareVersion.Major, info.HardwareVersion.Minor)
	resp.AppendVersion(info.FirmwareVersion.Major, info.FirmwareVersion.Minor)

	resp.AppendString("", 16)
	return resp, nil
}

func (s *Server) handleGetSlotInfo(req *rpc.Body) (*rpc.Body, error) {
	slotID, err := req.Ulong()
	if err != nil {
		return nil, fmt.Errorf("reading slot ID")
	}
	if err := req.Close(); err != nil {
		return nil, err
	}
	if s.GetSlotInfo == nil {
		return nil, ErrFunctionNotSupported
	}
	info, err := s.GetSlotInfo(SlotID(slotID))
	if err != nil {
		return nil, err
	}

	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959687
	var flags uint64
	if info.TokenPresent {
		flags |= 0x01
	}
	if info.RemovableDevice {
		flags |= 0x02
	}
	if info.HardwareSlot {
		flags |= 0x04
	}

	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L467
	resp := &rpc.Body{Call: rpc.CallGetSlotInfo}
	resp.AppendString(info.Description, 64)
	resp.AppendString(info.ManufacturerID, 32)
	resp.AppendUlong(flags)
	resp.AppendVersion(info.HardwareVersion.Major, info.HardwareVersion.Minor)
	resp.AppendVersion(info.FirmwareVersion.Major, info.FirmwareVersion.Minor)
	return resp, nil
}

func (s *Server) handleGetSlotList(req *rpc.Body) (*rpc.Body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L875

	tokenPresent, err := req.Byte()
	if err != nil {
		return nil, fmt.Errorf("reading token present byte: %v", err)
	}
	n, err := req.Buffer()
	if err != nil {
		return nil, fmt.Errorf("reading slot list: %v", err)
	}
	if err := req.Close(); err != nil {
		return nil, fmt.Errorf("processing response: %v", err)
	}
	if s.GetSlotList == nil {
		return nil, ErrFunctionNotSupported
	}
	list, err := s.GetSlotList(tokenPresent != 0)
	if err != nil {
		return nil, err
	}
	resp := &rpc.Body{Call: rpc.CallGetSlotList}
	if n == 0 {
		resp.AppendUlongsLength(len(list))
	} else if int(n) < len(list) {
		return nil, ErrBufferTooSmall
	} else {
		sli := make([]uint64, len(list))
		for i, id := range list {
			sli[i] = uint64(id)
		}
		resp.AppendUlongs(sli)
	}
	return resp, nil
}

func (s *Server) handleOpenSession(req *rpc.Body) (*rpc.Body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L980
	slotID, err := req.Ulong()
	if err != nil {
		return nil, fmt.Errorf("decode slot id: %v", err)
	}
	flags, err := req.Ulong()
	if err != nil {
		return nil, fmt.Errorf("decode flags: %v", err)
	}
	if err := req.Close(); err != nil {
		return nil, err
	}

	if s.OpenSession == nil {
		return nil, ErrFunctionNotSupported
	}
	sessionID, err := s.OpenSession(SlotID(slotID), flags)
	if err != nil {
		return nil, err
	}

	resp := &rpc.Body{Call: rpc.CallOpenSession}
	resp.AppendUlong(uint64(sessionID))
	return resp, nil
}

func (s *Server) handleCloseSession(req *rpc.Body) (*rpc.Body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L998
	id, err := req.Ulong()
	if err != nil {
		return nil, fmt.Errorf("decode session id: %v", err)
	}
	if err := req.Close(); err != nil {
		return nil, err
	}
	if s.CloseSession == nil {
		return nil, ErrFunctionNotSupported
	}
	if err := s.CloseSession(SessionID(id)); err != nil {
		return nil, err
	}

	resp := &rpc.Body{Call: rpc.CallCloseSession}
	return resp, nil
}

func writeByte(w io.Writer, b byte) error {
	if bw, ok := w.(io.ByteWriter); ok {
		return bw.WriteByte(b)
	}
	_, err := w.Write([]byte{b})
	return err
}

func readByte(r io.Reader) (byte, error) {
	if br, ok := r.(io.ByteReader); ok {
		return br.ReadByte()
	}
	var buf [1]byte
	_, err := io.ReadFull(r, buf[:])
	return buf[0], err
}

func negotiateProtocolVersion(rw io.ReadWriter) error {
	// Negotiation logic can be found at:
	//
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-server.c#L1944
	peerVersion, err := readByte(rw)
	if err != nil {
		return fmt.Errorf("reading protocol version: %v", err)
	}
	// Protocol used by the current P11 kit.
	const protocolVersion byte = 0
	if peerVersion != protocolVersion {
		return fmt.Errorf("client attempting to speak unsupported protocol version: %d", peerVersion)
	}
	if err := writeByte(rw, protocolVersion); err != nil {
		return fmt.Errorf("writing protocol version: %v", err)
	}
	return nil
}

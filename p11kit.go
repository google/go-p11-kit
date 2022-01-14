// Package p11kit implements the p11-kit RPC protocol.
package p11kit

import (
	"errors"
	"fmt"
	"io"
	"math"
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

// Version of the spec this package aims to implement.
var cryptokiVersion = Version{Major: 0x02, Minor: 0x28}

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

// Slot holds information about the slot and token.
type Slot struct {
	ID uint64

	Description  string
	Label        string
	Manufacturer string
	Model        string
	Serial       string

	HardwareVersion Version
	FirmwareVersion Version
}

// Server implements a server for the p11-kit PRC protocol.
type Server struct {
	Manufacturer   string
	Library        string
	LibraryVersion Version

	Slots []Slot
}

// handler holds per-handler data and multable state for a given client.
type handler struct {
	s *Server

	lastSessionID uint64

	sessions map[uint64]*session
}

type session struct {
	slotID uint64

	findMatches []uint64
}

func (h *handler) newSearch(sessionID uint64, tmpl []attribute) error {
	s, err := h.session(sessionID)
	if err != nil {
		return err
	}
	s.findMatches = []uint64{}
	return nil
}

func (h *handler) nextSearch(sessionID uint64, max int) ([]uint64, error) {
	s, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	m := s.findMatches
	if max >= len(m) {
		s.findMatches = nil
		return m, nil
	}
	s.findMatches = m[max:]
	return m[:max], nil
}

func (h *handler) newSession(slotID uint64) (uint64, error) {
	if _, err := h.slot(slotID); err != nil {
		return 0, err
	}

	if h.sessions == nil {
		h.sessions = make(map[uint64]*session)
	}

	nextSessionID := h.lastSessionID + 1
	for {
		if _, ok := h.sessions[nextSessionID]; !ok {
			break
		}
		nextSessionID++
	}
	h.lastSessionID = nextSessionID
	h.sessions[nextSessionID] = &session{
		slotID: slotID,
	}
	return nextSessionID, nil
}

func (h *handler) session(id uint64) (*session, error) {
	if len(h.sessions) == 0 {
		return nil, ErrSessionHandleInvalid
	}
	s, ok := h.sessions[id]
	if !ok {
		return nil, ErrSessionHandleInvalid
	}
	return s, nil
}

func (h *handler) closeSession(id uint64) error {
	if len(h.sessions) == 0 {
		return ErrSessionHandleInvalid
	}
	_, ok := h.sessions[id]
	delete(h.sessions, id)
	if !ok {
		return ErrSessionHandleInvalid
	}
	return nil
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

	h := &handler{s: s}

	done := false
	handlers := map[call]func(*body) (*body, error){
		callFinalize: func(req *body) (*body, error) {
			done = true
			return req, nil
		},
		callInitialize:       h.handleInitialize,
		callGetInfo:          h.handleGetInfo,
		callGetSlotList:      h.handleGetSlotList,
		callGetTokenInfo:     h.handleGetTokenInfo,
		callGetSlotInfo:      h.handleGetSlotInfo,
		callOpenSession:      h.handleOpenSession,
		callCloseSession:     h.handleCloseSession,
		callFindObjectsInit:  h.handleFindObjectsInit,
		callFindObjects:      h.handleFindObjects,
		callFindObjectsFinal: h.handleFindObjectsFinal,
	}

	for !done {
		callID, req, err := readRequest(rw)
		if err != nil {
			return fmt.Errorf("read request: %v", err)
		}
		var resp *body
		if h, ok := handlers[req.call]; ok {
			resp, err = h(req)
		} else {
			err = ErrFunctionNotSupported
		}
		if err != nil {
			var cerr Error
			if !errors.As(err, &cerr) {
				return fmt.Errorf("%d failed: %v", req.call, err)
			}

			// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L142-L143
			resp = &body{call: callError}
			resp.writeUlong(uint64(cerr))
		}
		if err := writeResponse(rw, callID, resp); err != nil {
			return fmt.Errorf("writing response: %v", err)
		}
	}
	return nil
}

func (h *handler) handleInitialize(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-message.h#L215
	const handshakeMessage = "PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1"

	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L774-L792

	var (
		handshake []byte
		reserved  byte
	)
	req.readByteArray(&handshake, nil)
	req.readByte(&reserved)
	req.readByteArray(nil, nil) // reserved data
	if err := req.err(); err != nil {
		return nil, err
	}
	if string(handshake) != handshakeMessage {
		return nil, fmt.Errorf("client sent unexpected handshake message: %s", handshake)
	}
	return newResponse(req), nil
}

func (h *handler) handleGetInfo(req *body) (*body, error) {
	if err := req.err(); err != nil {
		return nil, err
	}

	resp := newResponse(req)
	resp.writeVersion(cryptokiVersion)
	resp.writeString(h.s.Manufacturer, 32)
	resp.writeUlong(0) // Flags is always zero.
	resp.writeString(h.s.Library, 32)
	resp.writeVersion(h.s.LibraryVersion)
	return resp, nil
}

func (h *handler) handleGetTokenInfo(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L905
	var slotID uint64
	req.readUlong(&slotID)
	if err := req.err(); err != nil {
		return nil, err
	}

	slot, err := h.slot(slotID)
	if err != nil {
		return nil, err
	}

	// https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024051
	var flags uint64
	flags |= 0x00000002 // CKF_WRITE_PROTECTED
	flags |= 0x00000400 // CKF_TOKEN_INITIALIZED

	const (
		effectivelyInfinite    = 0x0
		unavailableInformation = math.MaxUint64
	)

	resp := newResponse(req)
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L484
	resp.writeString(slot.Label, 32)
	resp.writeString(slot.Manufacturer, 32)

	resp.writeString(slot.Model, 16)
	resp.writeString(slot.Serial, 16)

	resp.writeUlong(flags)

	resp.writeUlong(effectivelyInfinite)
	resp.writeUlong(unavailableInformation)
	resp.writeUlong(effectivelyInfinite)
	resp.writeUlong(unavailableInformation)

	// Zero values for PIN. We don't actually use these.
	resp.writeUlong(0)
	resp.writeUlong(0)

	resp.writeUlong(unavailableInformation)
	resp.writeUlong(unavailableInformation)
	resp.writeUlong(unavailableInformation)
	resp.writeUlong(unavailableInformation)

	resp.writeVersion(slot.HardwareVersion)
	resp.writeVersion(slot.FirmwareVersion)

	// TODO(ericchiang): Include time.
	resp.writeString("", 16)
	return resp, nil
}

func (h *handler) slot(id uint64) (Slot, error) {
	for _, slot := range h.s.Slots {
		if slot.ID == id {
			return slot, nil
		}
	}

	return Slot{}, ErrSlotIDInvalid
}

func (h *handler) handleGetSlotInfo(req *body) (*body, error) {
	var slotID uint64
	req.readUlong(&slotID)
	if err := req.err(); err != nil {
		return nil, err
	}

	slot, err := h.slot(slotID)
	if err != nil {
		return nil, err
	}

	// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959687
	var flags uint64
	flags |= 0x01 // CKF_TOKEN_PRESENT
	flags |= 0x04 // CKF_HW_SLOT

	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L467
	resp := newResponse(req)
	resp.writeString(slot.Description, 64)
	resp.writeString(slot.Manufacturer, 32)
	resp.writeUlong(flags)
	resp.writeVersion(slot.HardwareVersion)
	resp.writeVersion(slot.FirmwareVersion)
	return resp, nil
}

func (h *handler) handleGetSlotList(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L875
	var (
		tokenPresent byte
		n            uint32
	)
	req.readByte(&tokenPresent)
	req.readUlongBuffer(&n)
	if err := req.err(); err != nil {
		return nil, err
	}

	resp := newResponse(req)
	if n == 0 {
		resp.writeUlongArray(nil, uint32(len(h.s.Slots)))
	} else if int(n) < len(h.s.Slots) {
		return nil, ErrBufferTooSmall
	} else {
		sli := make([]uint64, len(h.s.Slots))
		for i, slot := range h.s.Slots {
			sli[i] = slot.ID
		}
		resp.writeUlongArray(sli, 0)
	}
	return resp, nil
}

func (h *handler) handleOpenSession(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L980
	var slotID, flags uint64
	req.readUlong(&slotID)
	req.readUlong(&flags)
	if err := req.err(); err != nil {
		return nil, err
	}

	// https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc72656119

	// Check for CKF_SERIAL_SESSION.
	if (flags & 0x00000004) == 0 {
		return nil, ErrSessionParallelNotSupported
	}

	sessionID, err := h.newSession(slotID)
	if err != nil {
		return nil, err
	}

	resp := newResponse(req)
	resp.writeUlong(sessionID)
	return resp, nil
}

func (h *handler) handleCloseSession(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L998
	var id uint64
	req.readUlong(&id)
	if err := req.err(); err != nil {
		return nil, err
	}
	if err := h.closeSession(id); err != nil {
		return nil, err
	}
	return newResponse(req), nil
}

func (h *handler) handleFindObjectsInit(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1215
	var (
		sessionID uint64
		tmpl      []attribute
	)
	req.readUlong(&sessionID)
	req.readAttributeArray(&tmpl)
	if err := req.err(); err != nil {
		return nil, err
	}
	if err := h.newSearch(sessionID, tmpl); err != nil {
		return nil, err
	}
	return newResponse(req), nil
}

func (h *handler) handleFindObjects(req *body) (*body, error) {
	var (
		sessionID uint64
		count     uint32
	)
	req.readUlong(&sessionID)
	req.readUlongBuffer(&count)
	if err := req.err(); err != nil {
		return nil, err
	}
	objIDs, err := h.nextSearch(sessionID, int(count))
	if err != nil {
		return nil, err
	}
	resp := newResponse(req)
	resp.writeUlongArray(objIDs, uint32(len(objIDs)))
	return resp, nil
}

func (h *handler) handleFindObjectsFinal(req *body) (*body, error) {
	var sessionID uint64
	req.readUlong(&sessionID)
	if err := req.err(); err != nil {
		return nil, err
	}
	return newResponse(req), nil
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

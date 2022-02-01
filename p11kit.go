// Package p11kit implements the p11-kit RPC protocol.
package p11kit

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
)

// pkcs11Error represents a PKCS #11 return code.
type pkcs11Error uint64

var errStrings = map[pkcs11Error]string{
	errSlotIDInvalid:        "invalid slot ID",
	errGeneralError:         "general error",
	errArgumentsBad:         "invalid function arguments",
	errFunctionNotSupported: "function not supported",
}

// Error returns a human readable message of the PKCS #11 return code.
func (e pkcs11Error) Error() string {
	if s, ok := errStrings[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown pkcs11 error: 0x%08x", uint64(e))
}

// Error codes defined PKCS #11.
//
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/csd02/pkcs11-base-v2.40-csd02.html#_Toc385435538
const (
	errCancel                        pkcs11Error = 0x00000001
	errHostMemory                    pkcs11Error = 0x00000002
	errSlotIDInvalid                 pkcs11Error = 0x00000003
	errGeneralError                  pkcs11Error = 0x00000005
	errFunctionFailed                pkcs11Error = 0x00000006
	errArgumentsBad                  pkcs11Error = 0x00000007
	errNoEvent                       pkcs11Error = 0x00000008
	errNeedToCreateThreads           pkcs11Error = 0x00000009
	errCantLock                      pkcs11Error = 0x0000000a
	errAttributeReadOnly             pkcs11Error = 0x00000010
	errAttributeSensitive            pkcs11Error = 0x00000011
	errAttributeTypeInvalid          pkcs11Error = 0x00000012
	errAttributeValueInvalid         pkcs11Error = 0x00000013
	errCopyProhibited                pkcs11Error = 0x0000001a
	errActionProhibited              pkcs11Error = 0x0000001b
	errDataInvalid                   pkcs11Error = 0x00000020
	errDataLenRange                  pkcs11Error = 0x00000021
	errDeviceError                   pkcs11Error = 0x00000030
	errDeviceMemory                  pkcs11Error = 0x00000031
	errDeviceRemoved                 pkcs11Error = 0x00000032
	errEncryptedDataInvalid          pkcs11Error = 0x00000040
	errEncryptedDataLenRange         pkcs11Error = 0x00000041
	errFunctionCanceled              pkcs11Error = 0x00000050
	errFunctionNotParallel           pkcs11Error = 0x00000051
	errFunctionNotSupported          pkcs11Error = 0x00000054
	errKeyHandleInvalid              pkcs11Error = 0x00000060
	errKeySizeRange                  pkcs11Error = 0x00000062
	errKeyTypeInconsistent           pkcs11Error = 0x00000063
	errKeyNotNeeded                  pkcs11Error = 0x00000064
	errKeyChanged                    pkcs11Error = 0x00000065
	errKeyNeeded                     pkcs11Error = 0x00000066
	errKeyIndigestible               pkcs11Error = 0x00000067
	errKeyFunctionNotPermitted       pkcs11Error = 0x00000068
	errKeyNotWrappable               pkcs11Error = 0x00000069
	errKeyUnextractable              pkcs11Error = 0x0000006a
	errMechanismInvalid              pkcs11Error = 0x00000070
	errMechanismParamInvalid         pkcs11Error = 0x00000071
	errObjectHandleInvalid           pkcs11Error = 0x00000082
	errOperationActive               pkcs11Error = 0x00000090
	errOperationNotInitialized       pkcs11Error = 0x00000091
	errPINIncorrect                  pkcs11Error = 0x000000a0
	errPINInvalid                    pkcs11Error = 0x000000a1
	errPINLenRange                   pkcs11Error = 0x000000a2
	errPINExpired                    pkcs11Error = 0x000000a3
	errPINLocked                     pkcs11Error = 0x000000a4
	errSessionClosed                 pkcs11Error = 0x000000b0
	errSessionCount                  pkcs11Error = 0x000000b1
	errSessionHandleInvalid          pkcs11Error = 0x000000b3
	errSessionParallelNotSupported   pkcs11Error = 0x000000b4
	errSessionReadOnly               pkcs11Error = 0x000000b5
	errSessionExists                 pkcs11Error = 0x000000b6
	errSessionReadOnlyExists         pkcs11Error = 0x000000b7
	errSessionReadWriteSoExists      pkcs11Error = 0x000000b8
	errSignatureInvalid              pkcs11Error = 0x000000c0
	errSignatureLenRange             pkcs11Error = 0x000000c1
	errTemplateIncomplete            pkcs11Error = 0x000000d0
	errTemplateInconsistent          pkcs11Error = 0x000000d1
	errTokenNotPresent               pkcs11Error = 0x000000e0
	errTokenNotRecognized            pkcs11Error = 0x000000e1
	errTokenWriteProtected           pkcs11Error = 0x000000e2
	errUnwrappingKeyHandleInvalid    pkcs11Error = 0x000000f0
	errUnwrappingKeySizeRange        pkcs11Error = 0x000000f1
	errUnwrappingKeyTypeInconsistent pkcs11Error = 0x000000f2
	errUserAlreadyLoggedIn           pkcs11Error = 0x00000100
	errUserNotLoggedIn               pkcs11Error = 0x00000101
	errUserPINNotInitialized         pkcs11Error = 0x00000102
	errUserTypeInvalid               pkcs11Error = 0x00000103
	errUserAnotherAlreadyLoggedIn    pkcs11Error = 0x00000104
	errUserTooManyTypes              pkcs11Error = 0x00000105
	errWrappedKeyInvalid             pkcs11Error = 0x00000110
	errWrappedKeyLenRange            pkcs11Error = 0x00000112
	errWrappingKeyHandleInvalid      pkcs11Error = 0x00000113
	errWrappingKeySizeRange          pkcs11Error = 0x00000114
	errWrappingKeyTypeInconsistent   pkcs11Error = 0x00000115
	errRandomSeedNotSupported        pkcs11Error = 0x00000120
	errRandomNoRNG                   pkcs11Error = 0x00000121
	errDomainParamsInvalid           pkcs11Error = 0x00000130
	errCurveNotSupported             pkcs11Error = 0x00000140
	errBufferTooSmall                pkcs11Error = 0x00000150
	errSavedStateInvalid             pkcs11Error = 0x00000160
	errInformationSensitive          pkcs11Error = 0x00000170
	errStateUnsaveable               pkcs11Error = 0x00000180
	errCryptokiNotInitialized        pkcs11Error = 0x00000190
	errCryptokiAlreadyInitialized    pkcs11Error = 0x00000191
	errMutexBad                      pkcs11Error = 0x000001a0
	errMutexNotLocked                pkcs11Error = 0x000001a1
	errFunctionRejected              pkcs11Error = 0x00000200
	errVendorDefined                 pkcs11Error = 0x80000000
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

// Slot is a logical grouping of objects, such as private keys and certificates.
type Slot struct {
	// ID is the unique identifier for the slot. It MUST be unique.
	ID uint64

	// Information that describes the slot/token.
	Description     string
	Label           string
	Manufacturer    string
	Model           string
	Serial          string
	HardwareVersion Version
	FirmwareVersion Version

	// Objects held by the slot.
	Objects []Object
	// GetObjects allows dynamically retrieving objects instead of statically
	// providing them as part of the Slot struct.
	//
	// This method is called once per-session, and the returned objects only
	// live for the duration of that session.
	GetObjects func() ([]Object, error)
}

// Handler implements a server for the p11-kit PRC protocol.
type Handler struct {
	// Manufacturer of the module. Limited to 32 bytes.
	Manufacturer string
	// Name of the module. Limited to 32 bytes.
	Library string
	// Internal version of the module. This is NOT the version of the PKCS #11
	// specification.
	LibraryVersion Version

	// Slots represents the slots/tokens the module provides. Slots hold
	// collections of objects, such as keys or certificates.
	//
	// This package doesn't currently support slots that don't have an underlying
	// token, and generally doesn't attempt to differentiate symantically between
	// slots and tokens.
	Slots []Slot
}

// handler holds per-connection data and multable state for a given client.
//
// Client requests are serialized across a single connection, so no locking is
// necessary.
type handler struct {
	s *Handler

	lastSessionID uint64
	sessions      map[uint64]*session
}

func (h *handler) newSession(slotID uint64) (uint64, error) {
	slot, err := h.slot(slotID)
	if err != nil {
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

	objects := slot.Objects
	if slot.GetObjects != nil {
		objs, err := slot.GetObjects()
		if err != nil {
			return 0, err
		}
		objects = objs
	}

	h.sessions[nextSessionID] = &session{
		objects: objects,
	}
	return nextSessionID, nil
}

func (h *handler) session(id uint64) (*session, error) {
	if len(h.sessions) == 0 {
		return nil, errSessionHandleInvalid
	}
	s, ok := h.sessions[id]
	if !ok {
		return nil, errSessionHandleInvalid
	}
	return s, nil
}

func (h *handler) closeSession(id uint64) error {
	if len(h.sessions) == 0 {
		return errSessionHandleInvalid
	}
	_, ok := h.sessions[id]
	delete(h.sessions, id)
	if !ok {
		return errSessionHandleInvalid
	}
	return nil
}

// session holds state for PKCS #11 sessions.
type session struct {
	objects []Object

	findMatches []uint64

	signMechanism mechanism
	signObject    Object
	signData      []byte
}

func (s *session) attributeValue(objectID uint64, tmpl []attributeTemplate) ([]attribute, error) {
	o, err := s.object(objectID)
	if err != nil {
		return nil, err
	}

	var attrs []attribute
	for _, t := range tmpl {
		a, ok := o.attributeValue(t.typ)
		if !ok {
			attrs = append(attrs, attribute{typ: t.typ})
			continue
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

func (s *session) object(objectID uint64) (Object, error) {
	for _, obj := range s.objects {
		if obj.id == objectID {
			return obj, nil
		}
	}
	return Object{}, errObjectHandleInvalid
}

func (s *session) find(sessionID uint64, tmpl []attribute) error {
objects:
	for _, o := range s.objects {
		for _, a := range tmpl {
			if !o.matches(a) {
				continue objects
			}
		}
		s.findMatches = append(s.findMatches, o.id)
	}
	return nil
}

func (s *session) findNext(sessionID uint64, max int) ([]uint64, error) {
	m := s.findMatches
	if max >= len(m) {
		s.findMatches = nil
		return m, nil
	}
	s.findMatches = m[max:]
	return m[:max], nil
}

// Handle begins serving RPC requests for a given connection.
func (s *Handler) Handle(rw io.ReadWriter) error {
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
		callInitialize:        h.handleInitialize,
		callGetInfo:           h.handleGetInfo,
		callGetSlotList:       h.handleGetSlotList,
		callGetTokenInfo:      h.handleGetTokenInfo,
		callGetSlotInfo:       h.handleGetSlotInfo,
		callOpenSession:       h.handleOpenSession,
		callCloseSession:      h.handleCloseSession,
		callFindObjectsInit:   h.handleFindObjectsInit,
		callFindObjects:       h.handleFindObjects,
		callFindObjectsFinal:  h.handleFindObjectsFinal,
		callGetAttributeValue: h.handleGetAttributeValue,
		callSignInit:          h.handleSignInit,
		callSign:              h.handleSign,
		callSignUpdate:        h.handleSignUpdate,
		callSignFinal:         h.handleSignFinal,
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
			err = errFunctionNotSupported
		}
		if err != nil {
			// TODO(ericchiang): refector so the logger is configured by Handler.
			log.Printf("Error with %s: %v", req.call, err)
			var cerr pkcs11Error
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

	return Slot{}, errSlotIDInvalid
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
		return nil, errBufferTooSmall
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
		return nil, errSessionParallelNotSupported
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
	s, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	if err := s.find(sessionID, tmpl); err != nil {
		return nil, err
	}
	return newResponse(req), nil
}

func (h *handler) handleFindObjects(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1228
	var (
		sessionID uint64
		count     uint32
	)
	req.readUlong(&sessionID)
	req.readUlongBuffer(&count)
	if err := req.err(); err != nil {
		return nil, err
	}
	s, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	objIDs, err := s.findNext(sessionID, int(count))
	if err != nil {
		return nil, err
	}
	if objIDs == nil {
		// For some reason the client doesn't like handling non-valid arrays.
		objIDs = []uint64{}
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

func (h *handler) handleGetAttributeValue(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1184
	var (
		sessionID uint64
		objectID  uint64
		attrs     []attributeTemplate
	)
	req.readUlong(&sessionID)
	req.readUlong(&objectID)
	req.readAttributeBuffer(&attrs)
	if err := req.err(); err != nil {
		return nil, err
	}

	s, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	arr, err := s.attributeValue(objectID, attrs)
	if err != nil {
		return nil, err
	}

	resp := newResponse(req)
	resp.writeAttributeArray(arr)
	// https://github.com/p11-glue/p11-kit/blob/0.24.1/p11-kit/rpc-server.c#L361
	resp.writeUlong(0)
	return resp, nil
}

func (h *handler) handleSignInit(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1467
	var (
		sessionID uint64
		m         mechanism
		keyID     uint64
	)
	req.readUlong(&sessionID)
	req.readMechanism(&m)
	req.readUlong(&keyID)
	if err := req.err(); err != nil {
		return nil, err
	}
	session, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	obj, err := session.object(keyID)
	if err != nil {
		return nil, err
	}
	if err := obj.supports(m); err != nil {
		return nil, err
	}
	session.signMechanism = m
	session.signObject = obj
	return newResponse(req), nil
}

func (h *handler) handleSign(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1481
	var (
		sessionID uint64
		data      []byte
		dataLen   uint32
		sigLen    uint32
	)
	req.readUlong(&sessionID)
	req.readByteArray(&data, &dataLen)
	req.readByteBuffer(&sigLen)
	if err := req.err(); err != nil {
		return nil, err
	}
	session, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	sig, err := session.signObject.sign(session.signMechanism, data)
	if err != nil {
		return nil, err
	}
	resp := newResponse(req)
	resp.writeByteArray(sig, uint32(len(sig)))
	return resp, nil
}

func (h *handler) handleSignUpdate(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1500
	var (
		sessionID uint64
		data      []byte
		dataLen   uint32
	)
	req.readUlong(&sessionID)
	req.readByteArray(&data, &dataLen)
	if err := req.err(); err != nil {
		return nil, err
	}
	session, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	session.signData = append(session.signData, data...)
	return newResponse(req), nil
}

func (h *handler) handleSignFinal(req *body) (*body, error) {
	// https://github.com/p11-glue/p11-kit/blob/0.24.0/p11-kit/rpc-client.c#L1515
	var (
		sessionID uint64
		sigLength uint32
	)
	req.readUlong(&sessionID)
	req.readByteBuffer(&sigLength)
	if err := req.err(); err != nil {
		return nil, err
	}
	session, err := h.session(sessionID)
	if err != nil {
		return nil, err
	}
	data, err := session.signObject.sign(session.signMechanism, session.signData)
	if err != nil {
		return nil, err
	}
	resp := newResponse(req)
	resp.writeByteArray(data, uint32(len(data)))
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

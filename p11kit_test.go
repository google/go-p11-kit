package p11kit

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	p11KitClientPath    = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
	p11KitEnvServerAddr = "P11_KIT_SERVER_ADDRESS"
	p11KitEnvServerPID  = "P11_KIT_SERVER_PID"
)

func testRequiresP11Tools(t *testing.T) {
	//	t.Skip("skipping e2e tests")
	if _, err := exec.LookPath("p11tool"); err != nil {
		t.Skip("p11tool not available, skipping test")
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

type testServer struct {
	initialized bool

	sessions map[SessionID]*testSession

	lastSessionID SessionID
}

func (t *testServer) server() *Server {
	return &Server{
		Initialize:   t.initialize,
		GetInfo:      t.getInfo,
		GetSlotList:  t.getSlotList,
		GetSlotInfo:  t.getSlotInfo,
		GetTokenInfo: t.getTokenInfo,
		OpenSession:  t.openSession,
		CloseSession: t.closeSession,
	}
}

type testSession struct {
	slotID SlotID
}

func (t *testServer) validSlot(id SlotID) error {
	switch id {
	case 0x01, 0x02:
		return nil
	default:
		return ErrSlotIDInvalid
	}
}

func (t *testServer) initialize(args *InitializeArgs) error {
	t.initialized = true
	return nil
}

func (t *testServer) getInfo() (*Info, error) {
	return &Info{
		CryptokiVersion: Version{
			Major: 0x02,
			Minor: 0x28,
		},
		Manufacturer: "test",
		Library:      "test_lib",
		LibraryVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
	}, nil
}

func (t *testServer) getSlotList(tokenPresent bool) ([]SlotID, error) {
	return []SlotID{0x01, 0x02}, nil
}

func (t *testServer) getSlotInfo(id SlotID) (*SlotInfo, error) {
	if err := t.validSlot(id); err != nil {
		return nil, err
	}
	return &SlotInfo{
		Description:     fmt.Sprintf("slot-%d", id),
		ManufacturerID:  "test",
		TokenPresent:    true,
		RemovableDevice: false,
		HardwareSlot:    false,
		HardwareVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
		FirmwareVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
	}, nil
}

func (t *testServer) getTokenInfo(id SlotID) (*TokenInfo, error) {
	if err := t.validSlot(id); err != nil {
		return nil, err
	}

	return &TokenInfo{
		Label:              fmt.Sprintf("token-%d", id),
		ManufacturerID:     "test",
		Model:              "test_mod",
		SerialNumber:       fmt.Sprintf("%d", id),
		Flags:              0,
		MaxSessionCount:    EffectivelyInfinite,
		SessionCount:       UnavailableInformation,
		MaxRWSessionCount:  EffectivelyInfinite,
		RWSessionCount:     UnavailableInformation,
		MaxPINLen:          10,
		MinPINLen:          4,
		TotalPublicMemory:  UnavailableInformation,
		FreePublicMemory:   UnavailableInformation,
		TotalPrivateMemory: UnavailableInformation,
		FreePrivateMemory:  UnavailableInformation,
		HardwareVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
		FirmwareVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
	}, nil
}

func (t *testServer) openSession(id SlotID, flags uint64) (SessionID, error) {
	if err := t.validSlot(id); err != nil {
		return 0, err
	}

	// TODO(ericchiang): check flags here

	if t.sessions == nil {
		t.sessions = make(map[SessionID]*testSession)
	}
	nextSessionID := t.lastSessionID + 1
	for {
		if _, ok := t.sessions[nextSessionID]; !ok {
			break
		}
		nextSessionID++
	}
	t.lastSessionID = nextSessionID
	t.sessions[nextSessionID] = &testSession{
		slotID: id,
	}
	return nextSessionID, nil
}

func (t *testServer) closeSession(id SessionID) error {
	_, ok := t.sessions[id]
	delete(t.sessions, id)
	if !ok {
		return ErrSessionHandleInvalid
	}
	return nil
}

func TestListTokens(t *testing.T) {
	testRequiresP11Tools(t)

	l, path := newListener(t)

	ts := testServer{}
	h := ts.server()

	errCh := make(chan error)
	go func() {
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
	cmd := exec.CommandContext(ctx, "p11tool",
		"--debug=9999",
		"--provider", p11KitClientPath,
		"--list-tokens")
	cmd.Env = append(os.Environ(),
		"P11_KIT_DEBUG=all",
		p11KitEnvServerPID+"="+strconv.Itoa(os.Getpid()),
		p11KitEnvServerAddr+"=unix:path="+path,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Errorf("command failed: %v: %s", err, &stderr)
	}
	if err := <-errCh; err != nil {
		t.Errorf("handle error: %v", err)
	}
}

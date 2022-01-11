package p11kit

import (
	"bytes"
	"context"
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
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not available, skipping test")
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
	sessions map[SessionID]*testSession

	lastSessionID SessionID
}

func (t *testServer) server() *Server {
	hwVersion := Version{0x01, 0x01}
	fwVersion := Version{0x02, 0x02}
	return &Server{
		Manufacturer: "test",
		Library:      "test_lib",
		LibraryVersion: Version{
			Major: 0x00,
			Minor: 0x01,
		},
		Slots: []Slot{
			{
				ID:              0x01,
				Label:           "slot-0x01",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x01",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
			},
			{
				ID:              0x02,
				Label:           "slot-0x02",
				Manufacturer:    "test_man",
				Model:           "test_model",
				Serial:          "serial-0x02",
				HardwareVersion: hwVersion,
				FirmwareVersion: fwVersion,
			},
		},

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

func TestPKCS11Tool(t *testing.T) {
	testRequiresP11Tools(t)

	tests := []struct {
		name string
		args []string
	}{
		{"ListSlots", []string{"--list-slots"}},
		{"ListTokenSlots", []string{"--list-token-slots"}},
		{"ListObjects", []string{"--list-objects"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			cmd := exec.CommandContext(ctx, "pkcs11-tool",
				append([]string{
					"--verbose",
					"--module", p11KitClientPath,
				}, test.args...)...)
			cmd.Env = append(os.Environ(),
				"P11_KIT_DEBUG=all",
				p11KitEnvServerPID+"="+strconv.Itoa(os.Getpid()),
				p11KitEnvServerAddr+"=unix:path="+path,
			)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Errorf("command failed: %v: %s", err, &stderr)
			} else {
				t.Logf("%s", &stdout)
			}
			if err := <-errCh; err != nil {
				t.Errorf("handle error: %v", err)
			}
		})
	}
}

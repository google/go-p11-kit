package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestWriteResponse(t *testing.T) {
	testCases := []struct {
		name     string
		callID   uint32
		callType Call
		fn       func(b *Body)
		want     []byte
	}{
		{
			name:     "Byte",
			callID:   0x10,
			callType: CallInitialize,
			fn: func(b *Body) {
				b.AppendByte(0x34)
			},
			want: []byte{
				0x00, 0x00, 0x00, 0x10, // Call ID
				0x00, 0x00, 0x00, 0x00, // Options length
				0x00, 0x00, 0x00, 0x0a, // Length of body (10 bytes)
				0x00, 0x00, 0x00, 0x01, // Call type
				0x00, 0x00, 0x00, 0x01, // Signature length
				'y',  // Signature
				0x34, // Value
			},
		},
		{
			name:     "Uint64",
			callID:   0x10,
			callType: CallInitialize,
			fn: func(b *Body) {
				b.AppendUlong(0x34)
			},
			want: []byte{
				0x00, 0x00, 0x00, 0x10, // Call ID
				0x00, 0x00, 0x00, 0x00, // Options length
				0x00, 0x00, 0x00, 0x11, // Length of body (17 bytes)
				0x00, 0x00, 0x00, 0x01, // Call type
				0x00, 0x00, 0x00, 0x01, // Signature length
				'u',                                            // Signature
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, // Value
			},
		},
		{
			name:     "Uint64s",
			callID:   0x10,
			callType: CallInitialize,
			fn: func(b *Body) {
				b.AppendUlongs([]uint64{0x34, 0x56})
			},
			want: []byte{
				0x00, 0x00, 0x00, 0x10, // Call ID
				0x00, 0x00, 0x00, 0x00, // Options length
				0x00, 0x00, 0x00, 0x1f, // Length of body (31 bytes)
				0x00, 0x00, 0x00, 0x01, // Call type
				0x00, 0x00, 0x00, 0x02, // Signature length
				'a', 'u', // Signature
				0x01,                   // Has content
				0x00, 0x00, 0x00, 0x02, // Number of elements
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, // Element 1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, // Element 2
			},
		},
		{
			name:     "Version",
			callID:   0x10,
			callType: CallInitialize,
			fn: func(b *Body) {
				b.AppendVersion(0x34, 0x56)
			},
			want: []byte{
				0x00, 0x00, 0x00, 0x10, // Call ID
				0x00, 0x00, 0x00, 0x00, // Options length
				0x00, 0x00, 0x00, 0x0b, // Length of body (11 bytes)
				0x00, 0x00, 0x00, 0x01, // Call type
				0x00, 0x00, 0x00, 0x01, // Signature length
				'v',  // Signature
				0x34, // Major
				0x56, // Minor
			},
		},
		{
			name:     "String",
			callID:   0x10,
			callType: CallInitialize,
			fn: func(b *Body) {
				b.AppendString("test", 16)
			},
			want: []byte{
				0x00, 0x00, 0x00, 0x10, // Call ID
				0x00, 0x00, 0x00, 0x00, // Options length
				0x00, 0x00, 0x00, 0x1d, // Length of body (29 bytes)
				0x00, 0x00, 0x00, 0x01, // Call type
				0x00, 0x00, 0x00, 0x01, // Signature length
				's',                    // Signature
				0x00, 0x00, 0x00, 0x10, // String length (16 bytes)
				't', 'e', 's', 't', ' ', ' ', ' ', ' ',
				' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Body{Call: tc.callType}
			tc.fn(b)
			buf := &bytes.Buffer{}
			WriteResponse(buf, tc.callID, b)

			got := buf.Bytes()

			if bytes.Equal(got, tc.want) {
				return
			}
			t.Errorf("WriteResponse wrote unexpected values, got\n%s\nwant\n%s", hex.Dump(got), hex.Dump(tc.want))

		})
	}
}

func TestReadRequest(t *testing.T) {
	message := []byte{
		0x00, 0x00, 0x00, 0x10, // Call ID
		0x00, 0x00, 0x00, 0x06, // Options length
		0x00, 0x00, 0x00, 0x42, // Body length
		0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, // "client"
		0x00, 0x00, 0x00, 0x01, // Call type
		0x00, 0x00, 0x00, 0x05, // Signature length
		0x61, 0x79, 0x79, 0x61, 0x79, // "ayyay"
		0x01,                   // Array has content
		0x00, 0x00, 0x00, 0x29, // Length of following message
		0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x2d, 0x47, 0x4e, 0x4f, 0x4d, 0x45, 0x2d, 0x4b, 0x45, 0x59, 0x52, 0x49, 0x4e, 0x47, 0x2d, 0x50, 0x4b, 0x43, 0x53, 0x31, 0x31, 0x2d, 0x50, 0x52, 0x4f, 0x54, 0x4f, 0x43, 0x4f, 0x4c, 0x2d, 0x56, 0x2d, 0x31,
		0x00,                   // "Reserved" byte
		0x01,                   // Array has content
		0x00, 0x00, 0x00, 0x01, // Length of Array
		0x00, // Content of array
	}
	id, b, err := ReadRequest(bytes.NewReader(message))
	if err != nil {
		t.Fatalf("ReadRequest() failed: %v", err)
	}
	wantID := uint32(0x10)
	if id != wantID {
		t.Errorf("ReadRequest() returned unexpected call, got %d, want %d", id, wantID)
	}
	if b.Call != CallInitialize {
		t.Errorf("ReadRequest() returned unexpected call, got %d, want %d", b.Call, CallInitialize)
	}
	wantSig := "ayyay"
	if b.signature != wantSig {
		t.Errorf("ReadRequest() returned unexpected signature, got %s, want %s", b.signature, wantSig)
	}

	protocol, err := b.Bytes()
	if err != nil {
		t.Fatalf("(*Body).Bytes() parsing protocol returned error: %v", err)
	}
	reserved, err := b.Byte()
	if err != nil {
		t.Fatalf("(*Body).Byte() parsing reserved byte returned error: %v", err)
	}
	if _, _, err := b.BytesOrLength(); err != nil {
		t.Fatalf("(*Body).Bytes() parsing reserved bytes returned error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("(*Body).Close() returned error: %v", err)
	}
	wantProtocol := []byte("PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1")
	if !bytes.Equal(protocol, wantProtocol) {
		t.Errorf("(*Body).Bytes() returned unexpected protocol, got %s, want %s", protocol, wantProtocol)
	}
	if reserved != 0 {
		t.Errorf("(*Body).Byte() returned unexpected reserved value, got %d, want 0", reserved)
	}
}

package ipc

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// frame builds a length-prefixed message (4-byte LE length + payload).
func frame(payload []byte) []byte {
	buf := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	return buf
}

func TestWriteReadRoundTrip(t *testing.T) {
	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	go func() {
		if err := WriteMessage(server, []byte(`{"command":"hello"}`)); err != nil {
			t.Error(err)
		}
		if err := WriteMessage(server, []byte(`{"n":2}`)); err != nil {
			t.Error(err)
		}
		server.Close()
	}()

	r := NewFrameReader(clientConn)
	msg, err := r.Read()
	if err != nil || string(msg) != `{"command":"hello"}` {
		t.Fatalf("first message: %q, %v", msg, err)
	}
	msg, err = r.Read()
	if err != nil || string(msg) != `{"n":2}` {
		t.Fatalf("second message: %q, %v", msg, err)
	}
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("expected EOF after close, got %v", err)
	}
}

// oneByteReader delivers data one byte at a time, like a socket splitting
// every write into the smallest possible chunks.
type oneByteReader struct{ data []byte }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestReadChunkedByteByByte(t *testing.T) {
	messages := [][]byte{
		[]byte(`{"command":"setupEncryption"}`),
		[]byte(`{"command":"getBiometricsStatusForUser"}`),
	}
	var wire []byte
	for _, m := range messages {
		wire = append(wire, frame(m)...)
	}
	r := NewFrameReader(&oneByteReader{data: wire})
	for i, want := range messages {
		got, err := r.Read()
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d: got %q want %q", i, got, want)
		}
	}
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReadMultipleFramesInOneChunk(t *testing.T) {
	wire := append(frame([]byte(`{"a":1}`)), frame([]byte(`{"b":2}`))...)
	r := NewFrameReader(bytes.NewReader(wire))
	for _, want := range []string{`{"a":1}`, `{"b":2}`} {
		got, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestReadTruncatedFrame(t *testing.T) {
	full := frame([]byte(`{"command":"x"}`))
	r := NewFrameReader(bytes.NewReader(full[:len(full)-3]))
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("expected EOF on truncated frame, got %v", err)
	}
}

// TestConnectAnnouncesClient checks that the first frame sent on a new
// connection is the client announcement the desktop app (>= 2026.10.2)
// requires, before any handshake message.
func TestConnectAnnouncesClient(t *testing.T) {
	// Unix socket paths are length-limited, so avoid the long t.TempDir().
	dir, err := os.MkdirTemp("", "bwbio")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s.bw")

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		first, err := NewFrameReader(conn).Read()
		if err != nil {
			got <- nil
			return
		}
		got <- first
	}()

	t.Setenv("BWBIO_IPC_SOCKET_PATH", path)
	conn, err := Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case first := <-got:
		if string(first) != `{"clientType":"cli"}` {
			t.Fatalf("first frame = %q, want the cli client announcement", first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the announcement frame")
	}
}

func TestWriteMessageLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	want := frame([]byte(`{"x":1}`))
	if !bytes.Equal(got, want) {
		t.Fatalf("wire bytes = %v, want %v", got, want)
	}
	if binary.LittleEndian.Uint32(got[:4]) != 7 {
		t.Fatalf("length prefix = %d, want 7", binary.LittleEndian.Uint32(got[:4]))
	}
}

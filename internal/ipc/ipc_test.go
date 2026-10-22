package ipc

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
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

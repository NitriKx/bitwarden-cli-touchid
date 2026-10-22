// Package ipc implements the framed transport to the Bitwarden desktop app:
// a Unix domain socket / named pipe carrying 4-byte little-endian
// length-prefixed JSON messages, plus socket path discovery.
package ipc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"bitwarden-bio/internal/log"
)

// maxMessageSize guards against absurd length prefixes (the original had none).
const maxMessageSize = 16 << 20

// FrameReader reads length-delimited messages: 4-byte LE length + JSON payload.
// It buffers partial reads, so frames split across chunk boundaries are safe.
type FrameReader struct {
	r   io.Reader
	buf []byte
}

// NewFrameReader wraps r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// Read returns the raw payload of the next complete message.
func (f *FrameReader) Read() ([]byte, error) {
	for {
		if msg, ok := f.extract(); ok {
			return msg, nil
		}
		chunk := make([]byte, 32*1024)
		n, err := f.r.Read(chunk)
		if n > 0 {
			f.buf = append(f.buf, chunk[:n]...)
		}
		if err != nil {
			// Deliver a final complete frame if the peer closed mid-stream.
			if msg, ok := f.extract(); ok {
				return msg, nil
			}
			return nil, err
		}
	}
}

func (f *FrameReader) extract() ([]byte, bool) {
	if len(f.buf) < 4 {
		return nil, false
	}
	length := binary.LittleEndian.Uint32(f.buf[:4])
	if length > maxMessageSize {
		// Poison the reader so subsequent calls fail fast.
		f.buf = nil
		f.r = errReader{}
		return nil, false
	}
	if uint64(len(f.buf)) < 4+uint64(length) {
		log.Debug("Waiting for more data")
		return nil, false
	}
	msg := append([]byte(nil), f.buf[4:4+length]...)
	f.buf = f.buf[4+length:]
	return msg, true
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("IPC message too large") }

// WriteMessage writes a length-prefixed message.
func WriteMessage(w io.Writer, payload []byte) error {
	buf := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

// SocketCandidates returns the desktop app IPC socket paths in lookup order.
func SocketCandidates() []string {
	if p := os.Getenv("BWBIO_IPC_SOCKET_PATH"); p != "" {
		return []string{p}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "~"
	}
	switch runtime.GOOS {
	case "windows":
		// Named pipe using a URL-safe base64 (unpadded) hash of the home dir.
		sum := sha256.Sum256([]byte(home))
		hash := base64.RawURLEncoding.EncodeToString(sum[:])
		return []string{`\\.\pipe\` + hash + ".s.bw"}
	case "darwin":
		// Sandboxed (App Store) build first, then direct download.
		return []string{
			filepath.Join(home, "Library", "Group Containers", "LTZ2PFU5D6.com.bitwarden.desktop", "s.bw"),
			filepath.Join(home, "Library", "Caches", "com.bitwarden.desktop", "s.bw"),
		}
	default:
		cacheDir := os.Getenv("XDG_CACHE_HOME")
		if cacheDir == "" {
			cacheDir = filepath.Join(home, ".cache")
		}
		return []string{filepath.Join(cacheDir, "com.bitwarden.desktop", "s.bw")}
	}
}

// Dial connects to a socket path (Unix socket, or named pipe on Windows).
func Dial(path string) (net.Conn, error) {
	if runtime.GOOS == "windows" {
		// Byte-mode named pipe; os.OpenFile is enough, no winio dependency.
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		return fileConn{f}, nil
	}
	return net.DialTimeout("unix", path, 5*time.Second)
}

// fileConn adapts an *os.File (named pipe) to net.Conn deadlines.
type fileConn struct{ *os.File }

func (fileConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (fileConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (fileConn) SetDeadline(time.Time) error      { return nil }
func (fileConn) SetReadDeadline(time.Time) error  { return nil }
func (fileConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "namedpipe" }

// Connect tries each candidate path in order and returns the first that works.
func Connect() (net.Conn, error) {
	for _, path := range SocketCandidates() {
		log.Verbose("Connecting to desktop app (via " + path + ")")
		conn, err := Dial(path)
		if err != nil {
			log.Verbose("Failed to connect: " + err.Error())
			continue
		}
		log.Debug("Socket connected: " + path)
		return conn, nil
	}
	return nil, errors.New(`Failed to connect to desktop app. Ensure the app is running and "Allow browser integration" is enabled in Desktop settings.`)
}

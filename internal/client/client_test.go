package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"bitwarden-bio/internal/bwcrypto"
	"bitwarden-bio/internal/ipc"
)

// fakeHandshake emulates the desktop app's setupEncryption reply: it reads the
// client's setup message, generates a 64-byte shared secret, RSA-OAEP(SHA-1)
// encrypts it with the client's public key, and replies. Returns the secret.
func fakeHandshake(t *testing.T, conn net.Conn, fr *ipc.FrameReader) []byte {
	t.Helper()
	raw, err := fr.Read()
	if err != nil {
		t.Errorf("fake desktop: read setup: %v", err)
		return nil
	}
	var setup outerMessage
	if err := json.Unmarshal(raw, &setup); err != nil {
		t.Errorf("fake desktop: parse setup: %v", err)
		return nil
	}
	var inner wireMessage
	if err := json.Unmarshal(setup.Message, &inner); err != nil || inner.Command != "setupEncryption" {
		t.Errorf("fake desktop: bad setup message: %v %q", err, setup.Message)
		return nil
	}
	pubRaw, err := base64.StdEncoding.DecodeString(inner.PublicKey)
	if err != nil {
		t.Errorf("fake desktop: public key: %v", err)
		return nil
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubRaw)
	if err != nil {
		t.Errorf("fake desktop: parse public key: %v", err)
		return nil
	}
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Errorf("fake desktop: %v", err)
		return nil
	}
	encSecret, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubAny.(*rsa.PublicKey), secret, nil)
	if err != nil {
		t.Errorf("fake desktop: %v", err)
		return nil
	}
	reply := outerMessage{
		AppID:        setup.AppID,
		Command:      "setupEncryption",
		SharedSecret: base64.StdEncoding.EncodeToString(encSecret),
	}
	if err := ipc.WriteMessage(conn, mustMarshal(reply)); err != nil {
		t.Errorf("fake desktop: write secret: %v", err)
		return nil
	}
	return secret
}

// fakeReply reads the next encrypted command and replies with a response.
func fakeReply(t *testing.T, conn net.Conn, fr *ipc.FrameReader, secret []byte, resp receivedMessage) {
	t.Helper()
	raw, err := fr.Read()
	if err != nil {
		t.Errorf("fake desktop: read command: %v", err)
		return
	}
	var msg outerMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Errorf("fake desktop: parse command: %v", err)
		return
	}
	recv, err := decodeMessage(msg.Message, secret)
	if err != nil || recv == nil {
		t.Errorf("fake desktop: decode command: %v", err)
		return
	}
	resp.Command = recv.Command
	resp.MessageID = recv.MessageID
	resp.Timestamp = time.Now().UnixMilli()
	payload, err := json.Marshal(resp)
	if err != nil {
		t.Errorf("fake desktop: %v", err)
		return
	}
	iv, ciphertext, mac, err := bwcrypto.Encrypt(payload, secret[:32], secret[32:])
	if err != nil {
		t.Errorf("fake desktop: %v", err)
		return
	}
	b64 := base64.StdEncoding.EncodeToString
	enc := encryptedPayload{
		EncryptionType:  bwcrypto.EncryptionType,
		EncryptedString: bwcrypto.EncryptedString(iv, ciphertext, mac),
		IV:              b64(iv),
		Data:            b64(ciphertext),
		Mac:             b64(mac),
	}
	if err := ipc.WriteMessage(conn, mustMarshal(outerMessage{AppID: msg.AppID, Message: mustMarshal(enc)})); err != nil {
		t.Errorf("fake desktop: write response: %v", err)
	}
}

func newTestClient(serverConn net.Conn) *Client {
	c := &Client{appID: "bwbio-test", userID: "user-1"}
	c.conn = serverConn
	c.reader = ipc.NewFrameReader(serverConn)
	return c
}

// TestUnlockDisconnectAfterKeyDelivery is the regression test for the bug in
// the original tool: the desktop app closes the socket right after delivering
// the user key, and the original crashed with an unhandled promise rejection
// AFTER printing the key. Here the key must be returned cleanly, with no
// error, and the disconnect must not be fatal.
func TestUnlockDisconnectAfterKeyDelivery(t *testing.T) {
	server, clientConn := net.Pipe()
	defer clientConn.Close()
	const wantKey = "dGhlLXVzZXIta2V5LWJhc2U2NC12YWx1ZQ=="
	go func() {
		defer server.Close()
		fr := ipc.NewFrameReader(server)
		secret := fakeHandshake(t, server, fr)
		if secret == nil {
			return
		}
		fakeReply(t, server, fr, secret, receivedMessage{
			Response:   json.RawMessage("true"),
			UserKeyB64: wantKey,
		})
		server.Close() // the desktop app closes right after delivering the key
	}()

	c := newTestClient(clientConn)
	key, err := c.UnlockWithBiometricsForUser("user-1")
	if err != nil {
		t.Fatalf("unlock must succeed despite disconnect after key delivery: %v", err)
	}
	if key != wantKey {
		t.Fatalf("user key = %q, want %q", key, wantKey)
	}
	c.Disconnect()
}

// TestUnlockDisconnectBeforeResponse: a disconnect while the response is still
// outstanding is a clean error (the caller falls back to regular bw unlock).
func TestUnlockDisconnectBeforeResponse(t *testing.T) {
	server, clientConn := net.Pipe()
	go func() {
		defer server.Close()
		fr := ipc.NewFrameReader(server)
		if fakeHandshake(t, server, fr) == nil {
			return
		}
		server.Close() // close without ever answering the unlock command
	}()

	c := newTestClient(clientConn)
	_, err := c.UnlockWithBiometricsForUser("user-1")
	if err == nil {
		t.Fatal("expected an error when the desktop disconnects before responding")
	}
	t.Logf("disconnect handled cleanly: %v", err)
}

// TestGetBiometricsStatusForUser exercises the silent status query end to end.
func TestGetBiometricsStatusForUser(t *testing.T) {
	server, clientConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		defer server.Close()
		fr := ipc.NewFrameReader(server)
		secret := fakeHandshake(t, server, fr)
		if secret == nil {
			return
		}
		fakeReply(t, server, fr, secret, receivedMessage{
			Response: json.RawMessage("0"), // Available
		})
	}()

	c := newTestClient(clientConn)
	status, err := c.GetBiometricsStatusForUser("user-1")
	if err != nil {
		t.Fatalf("status query: %v", err)
	}
	if status != StatusAvailable {
		t.Fatalf("status = %d, want %d (Available)", status, StatusAvailable)
	}
}

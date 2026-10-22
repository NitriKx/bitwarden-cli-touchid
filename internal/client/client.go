// Package client implements the native-messaging protocol used between the
// Bitwarden browser extension and the desktop app, mirroring
// src/ipc/native-messaging-client.ts:
//
//  1. Connect to the desktop app via Unix socket / named pipe.
//  2. Handshake: generate an RSA-2048 keypair, send the public key as
//     base64 SPKI/DER with appId+userId (command "setupEncryption"); the
//     desktop replies with sharedSecret encrypted RSA-OAEP (SHA-1).
//     The 64-byte sharedSecret = AES-256 key[0:32] + HMAC key[32:64].
//  3. Commands travel encrypted (encryptionType 2, AesCbc256_HmacSha256_B64)
//     with messageId + timestamp; responses older than ±10s are dropped.
//
// Unlike the original, this client is fully synchronous: one request is in
// flight at a time and there is no pending-callback map. A socket disconnect
// is therefore only ever observed while a response is still being waited
// for; once the user key has been delivered and returned, a subsequent
// disconnect is irrelevant (logged at debug level, never fatal).
package client

import (
	"bitwarden-bio/internal/bwcrypto"
	"bitwarden-bio/internal/fingerprint"
	"bitwarden-bio/internal/ipc"
	"bitwarden-bio/internal/log"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	handshakeTimeout       = 10 * time.Second // key exchange
	defaultTimeout         = 10 * time.Second // protocol messages
	userInteractionTimeout = 60 * time.Second // biometric prompts
	messageValidWindowMs   = 10 * 1000        // freshness window
)

// BiometricsStatus values, matching the desktop app's enum.
const (
	StatusAvailable                        = 0
	StatusUnlockNeeded                     = 1
	StatusHardwareUnavailable              = 2
	StatusAutoSetupNeeded                  = 3
	StatusManualSetupNeeded                = 4
	StatusPlatformUnsupported              = 5
	StatusDesktopDisconnected              = 6
	StatusNotEnabledLocally                = 7
	StatusNotEnabledInConnectedDesktopApp  = 8
	StatusNativeMessagingPermissionMissing = 9
)

// StatusName maps a status number to its enum name (for logs).
func StatusName(status int) string {
	names := map[int]string{
		StatusAvailable:                        "Available",
		StatusUnlockNeeded:                     "UnlockNeeded",
		StatusHardwareUnavailable:              "HardwareUnavailable",
		StatusAutoSetupNeeded:                  "AutoSetupNeeded",
		StatusManualSetupNeeded:                "ManualSetupNeeded",
		StatusPlatformUnsupported:              "PlatformUnsupported",
		StatusDesktopDisconnected:              "DesktopDisconnected",
		StatusNotEnabledLocally:                "NotEnabledLocally",
		StatusNotEnabledInConnectedDesktopApp:  "NotEnabledInConnectedDesktopApp",
		StatusNativeMessagingPermissionMissing: "NativeMessagingPermissionMissing",
	}
	if name, ok := names[status]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", status)
}

var errTimeout = errors.New("timed out")

// Client is a synchronous native-messaging client for the desktop app.
type Client struct {
	appID  string
	userID string
	conn   net.Conn
	reader *ipc.FrameReader
	priv   *rsa.PrivateKey
	pubDER []byte
	secret []byte // 64-byte shared secret once the handshake completes
	nextID int
}

// outerMessage is the frame envelope: {"appId": ..., "command": ..., ...}.
type outerMessage struct {
	AppID        string          `json:"appId"`
	Command      string          `json:"command,omitempty"`
	SharedSecret string          `json:"sharedSecret,omitempty"`
	Message      json.RawMessage `json:"message,omitempty"`
}

// wireMessage is the (optionally encrypted) inner command message we send.
type wireMessage struct {
	Command   string `json:"command"`
	MessageID int    `json:"messageId"`
	UserID    string `json:"userId,omitempty"`
	Timestamp int64  `json:"timestamp"`
	PublicKey string `json:"publicKey,omitempty"`
}

// encryptedPayload is the type-2 encrypted inner message on the wire.
type encryptedPayload struct {
	EncryptionType  int    `json:"encryptionType"`
	EncryptedString string `json:"encryptedString"`
	IV              string `json:"iv"`
	Data            string `json:"data"`
	Mac             string `json:"mac"`
}

// receivedMessage is a decrypted response from the desktop app.
type receivedMessage struct {
	Command    string          `json:"command"`
	MessageID  int             `json:"messageId"`
	Timestamp  int64           `json:"timestamp"`
	Response   json.RawMessage `json:"response"`
	UserKeyB64 string          `json:"userKeyB64"`
}

// NewAppID returns a unique app id for this CLI instance: "bwbio-<uuid>".
func NewAppID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("bwbio-%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// New creates a client for the given app id and user id.
func New(appID, userID string) *Client {
	return &Client{appID: appID, userID: userID}
}

// Connect connects to the desktop app, trying each socket candidate in order.
func (c *Client) Connect() error {
	conn, err := ipc.Connect()
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = ipc.NewFrameReader(conn)
	return nil
}

// Disconnect closes the socket (safe to call more than once).
func (c *Client) Disconnect() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.secret = nil
}

// GetBiometricsStatusForUser queries the biometrics status for a user
// (silent; does not trigger a biometric prompt).
func (c *Client) GetBiometricsStatusForUser(userID string) (int, error) {
	resp, err := c.call("getBiometricsStatusForUser", userID, defaultTimeout)
	if err != nil {
		return 0, err
	}
	var status float64
	if err := json.Unmarshal(resp.Response, &status); err != nil {
		return 0, fmt.Errorf("malformed status response: %w", err)
	}
	return int(status), nil
}

// UnlockWithBiometricsForUser requests a biometric unlock and returns the
// 64-byte user key (base64). Empty string means the unlock was denied.
func (c *Client) UnlockWithBiometricsForUser(userID string) (string, error) {
	resp, err := c.call("unlockWithBiometricsForUser", userID, userInteractionTimeout)
	if err != nil {
		return "", err
	}
	if !truthy(resp.Response) {
		return "", nil
	}
	return resp.UserKeyB64, nil
}

// Handshake performs the RSA key exchange with the desktop app.
func (c *Client) Handshake() error {
	if c.secret != nil {
		return nil
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	c.priv, c.pubDER = priv, der

	// The setup message is sent unencrypted, inside the appId envelope.
	setup := wireMessage{
		Command:   "setupEncryption",
		PublicKey: base64.StdEncoding.EncodeToString(der),
		UserID:    c.userID,
		MessageID: c.allocMessageID(),
		Timestamp: time.Now().UnixMilli(),
	}
	log.Debug("Sending setupEncryption")
	if err := c.post(outerMessage{AppID: c.appID, Message: mustMarshal(setup)}); err != nil {
		return err
	}

	deadline := time.Now().Add(handshakeTimeout)
	for {
		msg, err := c.readRaw(deadline)
		if err != nil {
			if errors.Is(err, errTimeout) {
				return errors.New("secure channel setup timed out")
			}
			return err
		}
		if msg == nil {
			continue
		}
		switch msg.Command {
		case "setupEncryption":
			if msg.AppID != c.appID || msg.SharedSecret == "" {
				continue
			}
			if err := c.establishSecret(msg.SharedSecret); err != nil {
				return err
			}
			return nil
		case "invalidateEncryption":
			if msg.AppID != c.appID {
				continue
			}
			return errors.New("encryption channel invalidated by desktop app")
		case "wrongUserId":
			return errors.New("account mismatch: CLI and desktop app are logged into different accounts")
		case "verifyDesktopIPCFingerprint":
			c.showFingerprint()
		default:
			// Not for us; keep waiting.
		}
	}
}

// establishSecret decrypts the RSA-OAEP (SHA-1) shared secret.
func (c *Client) establishSecret(sharedSecretB64 string) error {
	encrypted, err := base64.StdEncoding.DecodeString(sharedSecretB64)
	if err != nil {
		return err
	}
	secret, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.priv, encrypted, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt shared secret: %w", err)
	}
	if len(secret) != 64 {
		return fmt.Errorf("unexpected shared secret length: %d", len(secret))
	}
	c.secret = secret
	log.Debug(fmt.Sprintf("Decrypted sharedSecret length: %d", len(secret)))
	return nil
}

// call sends an encrypted command and waits for the matching response.
// There is exactly one request in flight, so a socket disconnect can only
// be observed while the response is still outstanding — once the response
// (e.g. the user key) has been returned, later disconnects are irrelevant.
func (c *Client) call(command, userID string, timeout time.Duration) (*receivedMessage, error) {
	if err := c.Handshake(); err != nil {
		return nil, err
	}

	inner := wireMessage{
		Command:   command,
		UserID:    userID,
		MessageID: c.allocMessageID(),
		Timestamp: time.Now().UnixMilli(),
	}
	payload, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	iv, ciphertext, mac, err := bwcrypto.Encrypt(payload, c.secret[:32], c.secret[32:])
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	enc := encryptedPayload{
		EncryptionType:  bwcrypto.EncryptionType,
		EncryptedString: bwcrypto.EncryptedString(iv, ciphertext, mac),
		IV:              b64(iv),
		Data:            b64(ciphertext),
		Mac:             b64(mac),
	}
	if err := c.post(outerMessage{AppID: c.appID, Message: mustMarshal(enc)}); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	for {
		msg, err := c.readRaw(deadline)
		if err != nil {
			if errors.Is(err, errTimeout) {
				return nil, errors.New("message timed out waiting for desktop app response")
			}
			// Disconnect while the response is still outstanding: only an
			// error (the caller falls back to regular bw unlock). If the key
			// was already delivered we never reach this point.
			log.Debug("Socket closed while waiting for response: " + err.Error())
			return nil, errors.New("disconnected from desktop app")
		}
		if msg == nil {
			continue
		}
		switch msg.Command {
		case "setupEncryption":
			// Desktop re-keying mid-session; mirror the original's handling.
			if msg.AppID == c.appID && msg.SharedSecret != "" {
				if err := c.establishSecret(msg.SharedSecret); err != nil {
					return nil, err
				}
			}
		case "invalidateEncryption":
			if msg.AppID != c.appID {
				continue
			}
			return nil, errors.New("encryption channel invalidated by desktop app")
		case "wrongUserId":
			return nil, errors.New("account mismatch: CLI and desktop app are logged into different accounts")
		case "verifyDesktopIPCFingerprint":
			c.showFingerprint()
		default:
			if msg.AppID != c.appID || len(msg.Message) == 0 {
				continue // ignore messages for other apps
			}
			recv, err := decodeMessage(msg.Message, c.secret)
			if err != nil {
				return nil, err
			}
			if recv == nil {
				continue
			}
			// Freshness window: ±10s.
			if abs(recv.Timestamp-time.Now().UnixMilli()) > messageValidWindowMs {
				log.Debug("Message too old, ignoring")
				continue
			}
			if recv.MessageID == inner.MessageID {
				return recv, nil
			}
			log.Debug(fmt.Sprintf("No callback found for messageId: %d", recv.MessageID))
		}
	}
}

// decodeMessage decrypts an encrypted payload (type 2) or passes through a
// plaintext received message, mirroring handleEncryptedMessage.
func decodeMessage(raw json.RawMessage, secret []byte) (*receivedMessage, error) {
	if secret == nil {
		return nil, nil
	}
	var probe struct {
		EncryptionType  int    `json:"encryptionType"`
		EncryptedString string `json:"encryptedString"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, nil // not an object we understand; ignore
	}
	inner := raw
	if probe.EncryptionType != 0 || probe.EncryptedString != "" {
		var enc encryptedPayload
		if err := json.Unmarshal(raw, &enc); err != nil {
			return nil, fmt.Errorf("malformed encrypted message: %w", err)
		}
		iv, err := base64.StdEncoding.DecodeString(enc.IV)
		if err != nil {
			return nil, err
		}
		data, err := base64.StdEncoding.DecodeString(enc.Data)
		if err != nil {
			return nil, err
		}
		mac, err := base64.StdEncoding.DecodeString(enc.Mac)
		if err != nil {
			return nil, err
		}
		plaintext, err := bwcrypto.Decrypt(iv, data, mac, secret[:32], secret[32:])
		if err != nil {
			return nil, err // includes ErrBadMAC -> "Message integrity check failed"
		}
		inner = plaintext
	}
	var recv receivedMessage
	if err := json.Unmarshal(inner, &recv); err != nil {
		return nil, fmt.Errorf("malformed response message: %w", err)
	}
	return &recv, nil
}

// post writes a framed message; a write failure tears down the channel state
// (same as postMessage in the original).
func (c *Client) post(msg outerMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err := ipc.WriteMessage(c.conn, payload); err != nil {
		c.secret = nil
		return err
	}
	return nil
}

// readRaw reads the next framed message, honoring the deadline. Malformed
// JSON is dropped with a debug log (same as the original socket layer).
func (c *Client) readRaw(deadline time.Time) (*outerMessage, error) {
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	payload, err := c.reader.Read()
	if err != nil {
		if os.IsTimeout(err) || errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, errTimeout
		}
		return nil, err
	}
	log.Debug("Received message: " + string(payload))
	var msg outerMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Debug("Failed to parse incoming IPC message as JSON")
		return nil, nil
	}
	return &msg, nil
}

// showFingerprint displays the desktop verification fingerprint, mirroring
// showFingerprint in the original.
func (c *Client) showFingerprint() {
	if c.pubDER == nil {
		return
	}
	formatted := fingerprint.Formatted(c.appID, c.pubDER)
	const cyan, bold, reset = "\x1b[36m", "\x1b[1m", "\x1b[0m"
	log.Log("")
	log.Log(bold + "Bitwarden Desktop App Verification" + reset)
	log.Log("Verify this fingerprint matches the one shown in the Desktop app:")
	log.Log("")
	log.Log("  " + cyan + formatted + reset)
	log.Log("")
	log.Log("Accept the connection in the Desktop app to continue.")
	log.Log("")
}

func (c *Client) allocMessageID() int {
	c.nextID++
	return c.nextID
}

func truthy(raw json.RawMessage) bool {
	s := string(raw)
	return s != "" && s != "null" && s != "false" && s != "0"
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // unreachable for these plain structs
	}
	return b
}

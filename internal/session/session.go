// Package session reads and writes the official bw CLI's data.json,
// mirroring src/session-storage.ts: the biometric user key is encrypted with a
// fresh random 64-byte session key and stored under
// "__PROTECTED__{userId}_user_auto" so the official CLI accepts the session.
package session

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"bitwarden-bio/internal/bwcrypto"
)

// DataDir returns the bw CLI data directory for the current platform.
func DataDir() string {
	if d := os.Getenv("BITWARDENCLI_APPDATA_DIR"); d != "" {
		if abs, err := filepath.Abs(d); err == nil {
			return abs
		}
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "~"
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Bitwarden CLI")
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = home
		}
		return filepath.Join(appData, "Bitwarden CLI")
	default:
		configDir := os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			configDir = filepath.Join(home, ".config")
		}
		return filepath.Join(configDir, "Bitwarden CLI")
	}
}

// GenerateSessionKey returns a fresh random 64-byte session key, base64
// encoded. This value IS the BW_SESSION the user exports.
func GenerateSessionKey() string {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(key)
}

// readData loads the CLI's data.json, returning an empty map if missing or
// unreadable (same as the original).
func readData() map[string]any {
	raw, err := os.ReadFile(filepath.Join(DataDir(), "data.json"))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil || data == nil {
		return map[string]any{}
	}
	return data
}

// writeData writes data.json with 2-space indent, mode 0600, preserving all
// other keys untouched.
func writeData(data map[string]any) error {
	dir := DataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return err
	}
	path := filepath.Join(dir, "data.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// ActiveUserID returns the active account id from the CLI's data.json.
func ActiveUserID() string {
	data := readData()
	if id, ok := data["global_account_activeAccountId"].(string); ok {
		return id
	}
	return ""
}

// StoreUserKeyForSession encrypts the biometric user key with the session key
// (Bitwarden type-2 protected format) and stores it in data.json under
// "__PROTECTED__{userId}_user_auto". This is what makes the official bw CLI
// accept the session key.
func StoreUserKeyForSession(userKeyB64, userID, sessionKey string) error {
	userKey, err := base64.StdEncoding.DecodeString(userKeyB64)
	if err != nil {
		return err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return err
	}
	protected, err := bwcrypto.EncryptProtectedString(userKey, keyBytes)
	if err != nil {
		return err
	}
	data := readData()
	data["__PROTECTED__"+userID+"_user_auto"] = protected
	return writeData(data)
}

package session

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"bitwarden-bio/internal/bwcrypto"
)

func withTempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", dir)
	return dir
}

func TestActiveUserID(t *testing.T) {
	dir := withTempDataDir(t)

	if id := ActiveUserID(); id != "" {
		t.Fatalf("ActiveUserID on missing data.json = %q, want empty", id)
	}

	data := map[string]any{"global_account_activeAccountId": "user-123"}
	raw, _ := json.Marshal(data)
	if err := os.WriteFile(filepath.Join(dir, "data.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if id := ActiveUserID(); id != "user-123" {
		t.Fatalf("ActiveUserID = %q, want %q", id, "user-123")
	}
}

func TestStoreUserKeyForSession(t *testing.T) {
	dir := withTempDataDir(t)

	// Pre-existing keys in data.json must be preserved.
	existing := map[string]any{"__PROTECTED__other_key": "existing-value", "global_account_activeAccountId": "user-123"}
	raw, _ := json.Marshal(existing)
	if err := os.WriteFile(filepath.Join(dir, "data.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	userKey := base64.StdEncoding.EncodeToString([]byte("the-64-byte-user-key-material-0123456789"))
	sessionKey := GenerateSessionKey()
	if decoded, err := base64.StdEncoding.DecodeString(sessionKey); err != nil || len(decoded) != 64 {
		t.Fatalf("session key should decode to 64 bytes, got %d (err %v)", len(decoded), err)
	}

	if err := StoreUserKeyForSession(userKey, "user-123", sessionKey); err != nil {
		t.Fatalf("StoreUserKeyForSession: %v", err)
	}

	// File mode must be 0600.
	info, err := os.Stat(filepath.Join(dir, "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("data.json mode = %o, want 600", info.Mode().Perm())
	}

	// The stored protected key must decrypt back to the user key with the
	// session key, in the format the official bw CLI reads.
	var data map[string]any
	rawBytes, _ := os.ReadFile(filepath.Join(dir, "data.json"))
	if err := json.Unmarshal(rawBytes, &data); err != nil {
		t.Fatal(err)
	}
	prot, ok := data["__PROTECTED__user-123_user_auto"].(string)
	if !ok {
		t.Fatalf("missing __PROTECTED__user-123_user_auto in data.json: %v", data)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := bwcrypto.DecryptProtectedString(prot, keyBytes)
	if err != nil {
		t.Fatalf("DecryptProtectedString: %v", err)
	}
	if base64.StdEncoding.EncodeToString(decrypted) != userKey {
		t.Fatalf("stored user key = %q, want %q", decrypted, userKey)
	}

	// Other keys preserved.
	if data["__PROTECTED__other_key"] != "existing-value" {
		t.Fatalf("existing key not preserved: %v", data)
	}
	if data["global_account_activeAccountId"] != "user-123" {
		t.Fatalf("existing key not preserved: %v", data)
	}
}

package bwcrypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testKeys(t *testing.T) (encKey, macKey, key64 []byte) {
	t.Helper()
	encKey = bytes.Repeat([]byte{1}, 32)
	macKey = bytes.Repeat([]byte{2}, 32)
	key64 = append(append([]byte{}, encKey...), macKey...)
	return
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	encKey, macKey, _ := testKeys(t)
	for _, plaintext := range [][]byte{
		[]byte("hello world"),
		[]byte(`{"command":"getBiometricsStatusForUser","messageId":1,"userId":"u","timestamp":123}`),
		{},
		bytes.Repeat([]byte{0xab}, 100), // multi-block
	} {
		iv, ciphertext, mac, err := Encrypt(plaintext, encKey, macKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if len(iv) != 16 {
			t.Fatalf("iv length = %d, want 16", len(iv))
		}
		got, err := Decrypt(iv, ciphertext, mac, encKey, macKey)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
		}
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	encKey, macKey, _ := testKeys(t)
	plaintext := []byte("secret")
	iv, ciphertext, mac, err := Encrypt(plaintext, encKey, macKey)
	if err != nil {
		t.Fatal(err)
	}
	mac[0] ^= 0xff
	if _, err := Decrypt(iv, ciphertext, mac, encKey, macKey); err != ErrBadMAC {
		t.Fatalf("tampered mac: got %v, want ErrBadMAC", err)
	}
	_, mac2, _, _ := Encrypt(plaintext, encKey, macKey)
	ciphertext[0] ^= 0xff
	if _, err := Decrypt(iv, ciphertext, mac2, encKey, macKey); err != ErrBadMAC {
		t.Fatalf("tampered ciphertext: got %v, want ErrBadMAC", err)
	}
}

func TestEncryptedStringFormat(t *testing.T) {
	encKey, macKey, _ := testKeys(t)
	iv, ciphertext, mac, _ := Encrypt([]byte("x"), encKey, macKey)
	s := EncryptedString(iv, ciphertext, mac)
	// Format: "2.<iv>|<data>|<mac>" with pipe-separated base64 parts
	// (matches the original native-messaging-client.ts).
	body, ok := strings.CutPrefix(s, "2.")
	if !ok {
		t.Fatalf("encryptedString = %q, want prefix %q", s, "2.")
	}
	parts := strings.Split(body, "|")
	if len(parts) != 3 {
		t.Fatalf("encryptedString = %q, want 3 pipe-separated parts", s)
	}
	if parts[0] != base64.StdEncoding.EncodeToString(iv) ||
		parts[1] != base64.StdEncoding.EncodeToString(ciphertext) ||
		parts[2] != base64.StdEncoding.EncodeToString(mac) {
		t.Fatalf("encryptedString parts mismatch: %q", s)
	}
}

func TestProtectedStringRoundTrip(t *testing.T) {
	_, _, key64 := testKeys(t)
	data := []byte("64-byte-user-key-base64-decoded-payload")
	protected, err := EncryptProtectedString(data, key64)
	if err != nil {
		t.Fatalf("EncryptProtectedString: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(protected)
	if err != nil {
		t.Fatal(err)
	}
	// Layout: [encType(1)][iv(16)][mac(32)][ciphertext].
	if len(raw) < 1+16+32+16 {
		t.Fatalf("protected string too short: %d", len(raw))
	}
	if raw[0] != EncryptionType {
		t.Fatalf("encType = %d, want 2", raw[0])
	}
	got, err := DecryptProtectedString(protected, key64)
	if err != nil {
		t.Fatalf("DecryptProtectedString: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round trip mismatch: got %q want %q", got, data)
	}
	if _, err := DecryptProtectedString(protected, bytes.Repeat([]byte{9}, 64)); err == nil {
		t.Fatal("decryption with wrong key should fail")
	}
}

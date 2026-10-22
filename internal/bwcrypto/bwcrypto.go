// Package bwcrypto implements Bitwarden's type-2 encryption format
// (AesCbc256_HmacSha256_B64): AES-256-CBC with HMAC-SHA256 over IV+ciphertext.
//
// Two encodings of the same primitive are used:
//   - Wire format: JSON fields {encryptionType, encryptedString, iv, data, mac},
//     with encryptedString rendered as "2.<iv>|<data>|<mac>" (base64 parts).
//   - Protected string (bw CLI data.json): base64 of
//     [encType(1)][iv(16)][mac(32)][ciphertext].
package bwcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// EncryptionType is Bitwarden's AesCbc256_HmacSha256_B64.
const EncryptionType = 2

// ErrBadMAC is returned when a message fails its integrity check.
var ErrBadMAC = errors.New("message integrity check failed")

// ErrBadKey is returned when a 64-byte key was expected but not provided.
var ErrBadKey = errors.New("session key must be 64 bytes")

// Encrypt encrypts plaintext with AES-256-CBC (PKCS#7 padded) and computes
// HMAC-SHA256 over iv||ciphertext with macKey.
func Encrypt(plaintext, encKey, macKey []byte) (iv, ciphertext, mac []byte, err error) {
	if len(encKey) != 32 || len(macKey) != 32 {
		return nil, nil, nil, ErrBadKey
	}
	iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// PKCS#7 padding (same as Node's aes-256-cbc).
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	mac = hmacSHA256(macKey, iv, ciphertext)
	return iv, ciphertext, mac, nil
}

// Decrypt verifies the HMAC-SHA256 over iv||ciphertext (constant-time) and
// decrypts the ciphertext with AES-256-CBC.
func Decrypt(iv, ciphertext, mac, encKey, macKey []byte) ([]byte, error) {
	if len(encKey) != 32 || len(macKey) != 32 {
		return nil, ErrBadKey
	}
	if len(iv) != aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 || len(ciphertext) == 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	if !hmac.Equal(mac, hmacSHA256(macKey, iv, ciphertext)) {
		return nil, ErrBadMAC
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
	padLen := int(padded[len(padded)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(padded) {
		return nil, errors.New("invalid padding")
	}
	for _, b := range padded[len(padded)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid padding")
		}
	}
	return padded[:len(padded)-padLen], nil
}

// EncryptedString renders the wire string "2.<iv>|<data>|<mac>" (base64 parts),
// matching the format the desktop app expects.
func EncryptedString(iv, ciphertext, mac []byte) string {
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("%d.%s|%s|%s", EncryptionType, b64(iv), b64(ciphertext), b64(mac))
}

// EncryptProtectedString encrypts data with a 64-byte key (encKey[0:32] +
// macKey[32:64]) and returns the bw CLI data.json protected-string encoding:
// base64 of [encType(1)][iv(16)][mac(32)][ciphertext].
func EncryptProtectedString(data, key64 []byte) (string, error) {
	if len(key64) != 64 {
		return "", ErrBadKey
	}
	iv, ciphertext, mac, err := Encrypt(data, key64[:32], key64[32:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, 1+16+32+len(ciphertext))
	out = append(out, EncryptionType)
	out = append(out, iv...)
	out = append(out, mac...)
	out = append(out, ciphertext...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptProtectedString reverses EncryptProtectedString.
func DecryptProtectedString(protected string, key64 []byte) ([]byte, error) {
	if len(key64) != 64 {
		return nil, ErrBadKey
	}
	raw, err := base64.StdEncoding.DecodeString(protected)
	if err != nil {
		return nil, err
	}
	if len(raw) < 1+16+32+aes.BlockSize || raw[0] != EncryptionType {
		return nil, errors.New("invalid protected string")
	}
	return Decrypt(raw[1:17], raw[49:], raw[17:49], key64[:32], key64[32:])
}

func hmacSHA256(key, iv, ciphertext []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	mac.Write(ciphertext)
	return mac.Sum(nil)
}

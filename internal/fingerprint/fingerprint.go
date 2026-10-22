// Package fingerprint generates the desktop-app verification fingerprint
// phrase, mirroring src/fingerprint.ts: SHA-256(publicKey) -> HKDF-Expand
// (RFC 5869, expand only) with the appId as info -> EFF long wordlist phrase.
package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"
	"math/big"
	"strings"
)

var wordList = strings.Fields(effLongWordList)

// Phrase returns the fingerprint words for the given material (appId) and
// public key (SPKI/DER bytes).
func Phrase(material string, publicKey []byte) []string {
	keyFingerprint := sha256.Sum256(publicKey)
	userFingerprint := hkdfExpand(keyFingerprint[:], material, 32)
	return hashPhrase(userFingerprint)
}

// Formatted returns the phrase joined with "-" (desktop app display format).
func Formatted(material string, publicKey []byte) string {
	return strings.Join(Phrase(material, publicKey), "-")
}

// hkdfExpand is the RFC 5869 expand step (SHA-256).
func hkdfExpand(prk []byte, info string, length int) []byte {
	const hashLen = 32
	n := (length + hashLen - 1) / hashLen
	okm := make([]byte, 0, n*hashLen)
	var prev []byte
	for i := 1; i <= n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write([]byte(info))
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length]
}

// hashPhrase converts a hash to a word phrase using the EFF Long Wordlist,
// matching Bitwarden's hashPhrase algorithm (64 bits minimum entropy -> 5 words).
func hashPhrase(hash []byte) []string {
	const minimumEntropy = 64
	entropyPerWord := math.Log2(float64(len(wordList)))
	numWords := int(math.Ceil(minimumEntropy / entropyPerWord))

	n := new(big.Int).SetBytes(hash)
	listLen := big.NewInt(int64(len(wordList)))
	mod := new(big.Int)
	phrase := make([]string, 0, numWords)
	for ; numWords > 0; numWords-- {
		n.DivMod(n, listLen, mod)
		phrase = append(phrase, wordList[mod.Int64()])
	}
	return phrase
}

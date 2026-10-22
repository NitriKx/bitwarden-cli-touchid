//go:build live

// Live protocol smoke test against the real Bitwarden desktop app socket.
//
// It performs ONLY the RSA handshake and the silent getBiometricsStatusForUser
// query — it never sends unlockWithBiometricsForUser, so no Touch ID prompt
// appears. Run with:
//
//	go test -tags live ./internal/client -run TestLive -v
package client

import (
	"fmt"
	"testing"

	"bitwarden-bio/internal/session"
)

func TestLiveHandshakeAndStatus(t *testing.T) {
	userID := session.ActiveUserID()
	if userID == "" {
		t.Skip("no active account in bw CLI data.json")
	}

	c := New(NewAppID(), userID)
	if err := c.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Disconnect()

	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Log("handshake ok: RSA-2048 keypair accepted, shared secret established")

	status, err := c.GetBiometricsStatusForUser(userID)
	if err != nil {
		t.Fatalf("getBiometricsStatusForUser: %v", err)
	}
	if status < 0 || status > StatusNativeMessagingPermissionMissing {
		t.Fatalf("status out of range: %d", status)
	}
	fmt.Println("biometrics status:", StatusName(status), "(", status, ")")
}

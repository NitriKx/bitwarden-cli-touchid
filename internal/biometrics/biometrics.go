// Package biometrics orchestrates a biometric unlock attempt via the desktop
// app, mirroring src/biometrics.ts.
package biometrics

import (
	"bitwarden-bio/internal/client"
	"bitwarden-bio/internal/log"
	"bitwarden-bio/internal/session"
	"runtime"
)

// Result of a biometric unlock attempt.
type Result struct {
	Success bool
	// UserKeyB64 is the user's encryption key (base64) — NOT the session key.
	UserKeyB64 string
	UserID     string
}

// biometricMethodName returns the platform-specific biometric method name.
func biometricMethodName() string {
	switch runtime.GOOS {
	case "darwin":
		return "Touch ID"
	case "windows":
		return "Windows Hello"
	default:
		return "Polkit"
	}
}

// AttemptBiometricUnlock tries to unlock the vault with biometrics via the
// desktop app. It never blocks the user: any failure returns Success=false so
// the caller can fall back to regular `bw unlock`.
func AttemptBiometricUnlock() Result {
	// The user id from the CLI data is required for the desktop app.
	userID := session.ActiveUserID()
	if userID == "" {
		log.Verbose("Biometric unlock unavailable: No user ID available - please log in first")
		return Result{}
	}

	c := client.New(client.NewAppID(), userID)
	if err := c.Connect(); err != nil {
		log.Verbose("Biometric unlock unavailable: " + err.Error())
		return Result{}
	}
	defer c.Disconnect()

	log.Verbose("Checking biometrics status...")
	status, err := c.GetBiometricsStatusForUser(userID)
	if err != nil {
		log.Log("Biometric unlock failed: " + err.Error())
		return Result{}
	}
	if status != client.StatusAvailable {
		log.Verbose("Biometric unlock unavailable: " + client.StatusName(status))
		return Result{}
	}

	log.Log("Authenticate with " + biometricMethodName() + " on Desktop app to continue...")

	userKey, err := c.UnlockWithBiometricsForUser(userID)
	if err != nil {
		log.Log("Biometric unlock failed: " + err.Error())
		return Result{}
	}
	if userKey == "" {
		log.Log("Biometric unlock was denied or failed")
		return Result{}
	}

	return Result{Success: true, UserKeyB64: userKey, UserID: userID}
}

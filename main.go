// bwbio: unlock the Bitwarden CLI vault via the desktop app's biometrics
// (Touch ID), then delegate every command to the official `bw` CLI.
//
// This is a Go port of jeanregisser/bitwarden-cli-bio v1.4.2 (MIT), with the
// desktop-disconnect-after-key-delivery crash fixed.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"bitwarden-bio/internal/biometrics"
	"bitwarden-bio/internal/session"
)

const version = "1.4.2"

// writeLn prints to stdout unless BW_QUIET=true (mirrors main.ts).
func writeLn(s string) {
	if os.Getenv("BW_QUIET") != "true" {
		fmt.Println(s)
	}
}

// executeBw runs the official bw CLI with the given args, inheriting stdio.
// If sessionKey is non-empty it is exported as BW_SESSION to the child.
func executeBw(args []string, sessionKey string) int {
	cmd := exec.Command("bw", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if sessionKey != "" {
		cmd.Env = append(cmd.Env, "BW_SESSION="+sessionKey)
	}
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Failed to execute bw: %v\n", err)
		return 1
	}
	return 0
}

// handleUnlock prints the session key export instructions for `bwbio unlock`.
func handleUnlock(args []string, sessionKey string) int {
	if contains(args, "--raw") {
		// Only the session key on stdout, so it can be captured.
		writeLn(sessionKey)
	} else {
		const greenBright, reset = "\x1b[92m", "\x1b[0m"
		writeLn(greenBright + "Your vault is now unlocked!" + reset + "\n")
		writeLn("To unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:")
		writeLn("$ export BW_SESSION=\"" + sessionKey + "\"")
		writeLn("> $env:BW_SESSION=\"" + sessionKey + "\"\n")
		writeLn("You can also pass the session key to any command with the `--session` option. ex:")
		writeLn("$ bw list items --session " + sessionKey)
	}
	return 0
}

func contains(args []string, arg string) bool {
	for _, a := range args {
		if a == arg {
			return true
		}
	}
	return false
}

func main() {
	os.Exit(run(os.Args[1:]))
}

// run mirrors main() in src/main.ts.
func run(args []string) int {
	if contains(args, "--bwbio-version") {
		writeLn(version)
		return 0
	}

	// Mirror --quiet and --nointeraction flags to env vars (same as bw CLI).
	if contains(args, "--quiet") {
		os.Setenv("BW_QUIET", "true")
	}
	if contains(args, "--nointeraction") {
		os.Setenv("BW_NOINTERACTION", "true")
	}

	// Skip biometric unlock when not needed or not possible.
	// Note: explicit 'unlock' always attempts biometrics, even if BW_SESSION
	// is set (e.g. after lock -> unlock in the same shell session).
	isUnlockCommand := len(args) > 0 && args[0] == "unlock"
	if (os.Getenv("BW_SESSION") != "" && !isUnlockCommand) ||
		os.Getenv("BW_NOINTERACTION") == "true" ||
		isPassthroughCommand(args) {
		return executeBw(args, "")
	}

	// Attempt biometric unlock.
	result := biometrics.AttemptBiometricUnlock()
	if !result.Success {
		// Biometric unlock failed or unavailable - fall back to regular bw CLI
		// (the user types the master password). Never block the user.
		return executeBw(args, "")
	}

	// Generate a new session key and store the user key.
	sessionKey := session.GenerateSessionKey()
	if err := session.StoreUserKeyForSession(result.UserKeyB64, result.UserID, sessionKey); err != nil {
		fmt.Fprintln(os.Stderr, "Unexpected error:", err)
		return 1
	}

	if isUnlockCommand {
		return handleUnlock(args, sessionKey)
	}
	return executeBw(args, sessionKey)
}

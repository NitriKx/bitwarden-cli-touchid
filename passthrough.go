package main

// Passthrough command detection (mirrors src/passthrough.ts): these commands
// are passed directly to `bw` without attempting biometric unlock.

var passthroughCommands = map[string]bool{
	"login":      true,
	"logout":     true,
	"lock":       true,
	"config":     true,
	"update":     true,
	"completion": true,
	"status":     true,
	"serve":      true,
}

var passthroughFlags = map[string]bool{
	"--help":    true,
	"-h":        true,
	"--version": true,
	"-v":        true,
}

// isPassthroughCommand reports whether the args need no unlocked vault:
// commands that don't need biometrics (login, logout, status, ...) and help or
// version flags anywhere in the args.
func isPassthroughCommand(args []string) bool {
	if len(args) == 0 {
		return true // no args = show help, which is passthrough
	}
	for _, arg := range args {
		if passthroughFlags[arg] {
			return true
		}
	}
	return passthroughCommands[args[0]]
}

# bwbio — Bitwarden CLI with biometric unlock

`bwbio` unlocks the Bitwarden CLI vault using the Bitwarden desktop app's
biometrics (Touch ID) — over the same IPC channel the browser extension uses —
and then delegates every command to the official `bw` CLI with `BW_SESSION` set.

This is a Go port of [jeanregisser/bitwarden-cli-bio](https://github.com/jeanregisser/bitwarden-cli-bio)
v1.4.2 (MIT), with one bug fixed: the original crashed with an unhandled
promise rejection when the desktop app closed the socket right after
delivering the user key (which it does) — after the key had already been
printed. In this port the IPC client is fully synchronous, so a disconnect
after key delivery is a clean path: the key is returned, nothing is pending,
and the process exits 0.

## Build

```sh
go build -o bwbio .
```

- Go 1.27, `CGO_ENABLED=0`, standard library only — no third-party
  dependencies (deliberate: this is a security-sensitive tool).
- Requires the official `bw` CLI on the PATH and the Bitwarden desktop app
  with "Enable browser integration" (and biometric unlock) enabled.

## Usage

```sh
bwbio <any bw command>     # e.g. bwbio list items
bwbio unlock               # Touch ID prompt; prints export instructions
export BW_SESSION=$(bwbio unlock --raw)   # capture only the session key
```

Behavior:

- Commands that skip biometrics and go straight to `bw`: `login`, `logout`,
  `lock`, `config`, `update`, `completion`, `status`, `serve`, and
  `--help`/`-h`/`--version`/`-v`.
- If `BW_SESSION` is already set, biometrics are skipped (except `unlock`,
  which always attempts biometrics).
- If biometrics fail for any reason (desktop app closed, socket error, user
  cancels the prompt, biometrics unavailable), `bwbio` falls back to delegating
  `bw unlock` with inherited stdio — the user types the master password. It
  never blocks the user.

## Environment variables

| Variable                        | Effect                                   |
| ------------------------------- | ---------------------------------------- |
| `BW_SESSION`                    | Skip biometrics (pass through to `bw`)   |
| `BWBIO_IPC_SOCKET_PATH`         | Override the desktop app IPC socket path |
| `BWBIO_VERBOSE` / `BWBIO_DEBUG` | Verbose/debug logging to stderr          |
| `BW_NOINTERACTION=true`         | Skip biometric attempts                  |
| `BW_QUIET=true`                 | Suppress informational messages          |

## Protocol (what the desktop app expects)

1. Socket candidates (macOS, in order): `$BWBIO_IPC_SOCKET_PATH` if set;
   `~/Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw`
   (App Store build); `~/Library/Caches/com.bitwarden.desktop/s.bw`
   (direct download).
2. Framing: 4-byte little-endian length prefix + JSON payload, both
   directions, chunk-safe.
3. Announcement: the first frame on every connection must be
   `{"clientType":"cli"}`. Desktop >= 2026.10.2 drops connections that do not
   announce themselves first (`Client did not announce itself, dropping
   connection` in the desktop `app.log`; `bwbio` then reports
   `Biometric unlock failed: EOF`).
4. Handshake: RSA-2048 keypair; the public key (base64 SPKI/DER) plus
   `appId` + `userId` is sent as `setupEncryption`. The desktop app replies
   with `sharedSecret` encrypted RSA-OAEP (SHA-1). The 64-byte shared secret
   is the AES-256 key `[0:32]` + HMAC-SHA256 key `[32:64]`.
5. Commands travel encrypted (`encryptionType: 2`, AES-256-CBC +
   HMAC-SHA256 over IV+ciphertext). `getBiometricsStatusForUser` must return
   status 0 (Available) before `unlockWithBiometricsForUser` is sent.
   Messages carry `messageId` + `timestamp`; responses outside a ±10s
   window are dropped; 60s is allowed for the biometric prompt.
6. The unlock response carries `userKeyB64` (the 64-byte user key).
7. A fresh random 64-byte session key is generated (it is the `BW_SESSION`
   value, base64). The user key is encrypted with it (type-2 protected
   format) and stored in the official `bw` CLI's `data.json` under
   `__PROTECTED__{userId}_user_auto`, preserving the rest of the file, mode 0600. This is what makes the official CLI accept the session key.

## Manual test

The automated tests never trigger a biometric prompt. After building:

```sh
./bwbio status                          # passthrough to bw, no biometrics
BW_NOINTERACTION=true ./bwbio unlock    # fallback: bw asks for the password
./bwbio unlock --raw                    # Touch ID prompt; prints only the key
```

A silent live-protocol smoke test (handshake + status query only, no Touch ID
prompt) is available with the `live` build tag, run against the running
desktop app:

```sh
go test -tags live ./internal/client -run TestLive -v
```

## Tests

```sh
go test ./...   # crypto round-trips, framing, fingerprint vector, session storage, disconnect-after-key regression
```

## Development

Requires [Task](https://taskfile.dev), Go 1.27, and (via `task setup`)
pre-commit, golangci-lint, and goreleaser.

```sh
task setup         # one-time: install tools + git hooks
task ci            # build, vet, lint, test -race (same as CI)
task pre-commit    # all hooks on all files
task snapshot      # local goreleaser build, all platforms, no publish
```

Commits must follow [Conventional Commits](https://www.conventionalcommits.org/)
(enforced by a commit-msg hook and by CI). See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

## Releases

Releases are automated with
[release-please](https://github.com/googleapis/release-please) from
conventional commit messages: merge the standing `chore(main): release X.Y.Z`
PR and the `vX.Y.Z` tag + GitHub release (binaries for darwin/linux/windows on
amd64/arm64) are created automatically. The current version lives in
`main.go` (`var Version`) and is stamped into release binaries at build time.

## License

MIT — see [LICENSE](LICENSE). Original TypeScript implementation:
Copyright (c) 2026 Jean Regisser.

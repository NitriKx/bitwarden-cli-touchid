# Contributing

Thanks for contributing to `bwbio`. This document covers the development
workflow: local tooling, commit conventions, CI, dependency updates, and how
releases work.

## Local setup

```sh
task setup        # installs pre-commit, golangci-lint, goreleaser + hooks
task build        # go build -o bwbio .
task test         # go test -race ./...
```

Useful tasks (`task --list` for the full list):

| Task                 | What it does                                 |
| -------------------- | -------------------------------------------- |
| `task ci`            | Full local pipeline: build, vet, lint, test  |
| `task lint`          | `golangci-lint run ./...`                    |
| `task fmt`           | `golangci-lint fmt ./...` (gofumpt)          |
| `task pre-commit`    | All pre-commit hooks on all files            |
| `task snapshot`      | Local goreleaser snapshot build (no publish) |
| `task release:check` | Validate the goreleaser config               |
| `task clean`         | Remove build artifacts                       |

## Commit conventions (required)

Commits **must** follow [Conventional Commits](https://www.conventionalcommits.org/).
This is what drives versioning and the changelog — it is enforced three ways:

1. **Locally**, the `conventional-pre-commit` hook validates every commit message.
2. **In CI**, `commitlint` checks every commit in a PR.
3. **In CI**, the PR **title** must be a valid conventional commit — because
   merges are squash-only, the PR title becomes the commit that release-please
   parses.

Examples:

```
feat: add --json output to unlock
fix(ipc): handle desktop disconnect after key delivery
docs: clarify BW_SESSION behavior in README
chore: bump golangci-lint to v2
```

Breaking changes: use `feat!:` / `fix!:` or add a `BREAKING CHANGE:` footer.

At version `0.x`, `feat:` bumps the minor (`0.2.0`), `fix:` bumps the patch
(`0.1.1`), and a breaking change bumps to `1.0.0`.

**Merges to `main` must be squash merges** (linear history is enforced by
branch protection). The PR title is the commit message, so keep it conventional.

## How releases work

Releases are managed by [release-please](https://github.com/googleapis/release-please)
from conventional commits — **no manual version bumps, no manual changelogs**.

1. Land PRs on `main` with conventional commit titles.
2. release-please maintains a standing **Release PR**
   (`chore(main): release X.Y.Z`) that accumulates the changelog and bumps
   `main.go`'s `Version` constant.
3. **You merge the Release PR yourself** (squash). That creates the `vX.Y.Z`
   tag and a **draft** GitHub release with the notes.
4. The `release-please.yml` workflow's `goreleaser` job then builds the binaries
   (darwin/linux/windows × amd64/arm64), adopts the draft release, uploads the
   archives + `checksums.txt`, and publishes it.

The current version lives in exactly one source-controlled place:
`var Version = "..." // x-release-please-version` in `main.go`. The
release binary gets the tag version stamped in at build time
(`-ldflags "-X main.Version=..."`), so `--bwbio-version` always matches the
release tag.

The baseline tag is `v0.1.0`. The version sequence restarts from the upstream
TypeScript project's 1.4.2 on purpose — this is the Go port's own versioning.

## Dependency updates (Renovate)

[Renovate](https://docs.renovatebot.com/) opens PRs for Go module, GitHub
Actions, and pre-commit hook updates, pinned to commit digests, with a 3-day
`minimumReleaseAge` cool-down.

- **Minor/patch/pin/digest updates automerge** once CI is green (platform
  automerge). You can see them in the Dependency Dashboard issue.
- **Major updates never automerge** — they wait for your review.
- The release-please Release PR is **not** a Renovate PR and is never
  automerged — merge it manually.

## Repository setup (one-time, for maintainers)

These steps can't be done from files in the repo:

1. **Renovate**: install the [Renovate GitHub App](https://github.com/apps/renovate)
   on this repository, then merge its "Configure Renovate" PR.
2. **Release token**: create a fine-grained PAT with _Contents: write_,
   _Pull requests: write_, _Metadata: read_ (no expiration if possible), and
   add it as the repository secret **`RELEASE_PLEASE_TOKEN`**. release-please
   opens its Release PR with this token instead of `GITHUB_TOKEN` so that CI
   runs on bot-authored PRs without manual approval. (PATs expire; if that
   becomes a problem, swap in a GitHub App like `actions/create-github-app-token`.)
3. **Branch protection on `main`**:
   - Require status checks: the jobs in `ci.yml` — `test`, `lint`,
     `pre-commit`, `conventions`, `release-check` (at least one required check
     is mandatory for platform automerge to be safe).
   - ✅ Allow auto-merge (required for Renovate platform automerge).
   - ✅ Require linear history (squash-only; merge commits would break
     release-please's commit parsing).
   - Either no required reviews, or add `renovate[bot]` (and the release
     token's user) to the "allow specified actors to bypass" list — otherwise
     automerge is blocked by the review requirement.
4. **First push**: after the CI config lands, verify release-please stays
   quiet (the `v0.1.0` tag marks everything released). Exercise the full flow
   with a small `fix:` commit: release-please opens a Release PR → merge it →
   the release appears with 6 binaries + `checksums.txt`.

## Reporting issues

Please include the output of `bwbio --bwbio-version`, your OS/architecture,
and (with `BWBIO_DEBUG=true`) debug logs with secrets redacted.

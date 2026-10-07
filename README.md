# TouchSign

Verification, policy, and anomaly-detection for git commits signed with a
FIDO2 hardware key -- a signal of physical human presence at commit time,
built entirely on git's own native SSH commit-signing support.

> **Status: portfolio / scaffold project.** This code has been written but
> has not been built, run, or tested. See "What has and hasn't been done"
> below before treating anything here as working software.

## Problem statement

Maintainers of active open-source and internal repositories are seeing a
rising flood of pull requests that are cheap to generate (an LLM can
produce a plausible-looking diff and commit message in seconds) and
expensive to review. Existing "prove you're human" approaches -- video
calls, biometric enrollment, CAPTCHAs -- don't fit a developer workflow:
nobody wants to join a video call to submit a one-line fix, and biometric
enrollment is a heavyweight, privacy-sensitive ask for a git contributor.

What developer workflows *already have*, though, is git commit signing, and
FIDO2 hardware authenticators already provide a "physical touch required"
guarantee at the protocol level (CTAP2 user presence). Nobody has to build
new cryptography, run a video call, or collect biometric data to get "a
human physically pressed a key for this specific operation" -- OpenSSH and
git already do this, today, for free.

TouchSign is the layer that makes that existing guarantee *useful as a
repository policy signal*: it verifies commit signatures, detects when the
timing between signatures is physically implausible for a human, applies
per-path coverage policy, and reports the result on the pull request.

## Architecture overview

```
contributor's git commit
  --(gpg.format=ssh, commit.gpgsign=true)-->
  SSH agent / ssh-keygen
  --(CTAP2 "get assertion", requires physical touch)-->
  FIDO2 authenticator (sk-ssh-ed25519 resident key)
       |
       v
  signed commit pushed to a PR
       |
       v
  CI runs `touchsign check`
    -> internal/verify   : git verify-commit / git log --show-signature
    -> internal/registry : allowed_signers lookup
    -> internal/anomaly  : per-signer signing-cadence timing floor
    -> internal/policy   : path_glob rules, coverage %, anomaly gate
    -> internal/report   : human summary + JSON, posted as a PR comment
       |
       v
  merge decision (policy Allowed=true/false + human reviewer)
```

See `docs/architecture.md` for a fuller diagram and component breakdown,
and `docs/adr/0001-why-ssh-signing-not-custom-webauthn.md` for why this
project deliberately does **not** implement WebAuthn/CTAP2 itself.

## Components

| Path | Responsibility |
|---|---|
| `internal/registry` | Read/write git's native `allowed_signers` format; enrollment and revocation are pull requests, not a new service. |
| `internal/verify` | Shell out to `git verify-commit` / `git log --show-signature` / `git rev-list`; parse into `CommitVerification`. |
| `internal/anomaly` | **Centerpiece.** Flag same-signer commit pairs signed faster than a human can physically press a security key twice. |
| `internal/policy` | Load a YAML policy; evaluate path-glob coverage requirements and anomaly gating. |
| `internal/report` | Build a human summary + JSON report; post it as a PR comment via `github.com/google/go-github/v66`. |
| `cmd/touchsign` | CLI (`touchsign check ...`) tying the above together. |
| `action.yml` + `Dockerfile` | Docker-based GitHub Action packaging for CI. |

## Setup (what WOULD be run -- none of this has been executed)

```sh
# 1. Generate a FIDO2-resident SSH signing key (requires a touch-capable
#    hardware authenticator plugged in).
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "you@example.com"

# 2. Tell git to sign commits with SSH keys, using that key.
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git config --global commit.gpgsign true

# 3. Enroll: add a line to this repo's allowed_signers file (see
#    internal/registry's doc comment) and open a PR, same as any other
#    change.

# 4. Build TouchSign itself. This module was authored by hand (see go.mod's
#    comment) and has never had `go mod tidy` run against it, so there is
#    no go.sum yet.
go mod tidy
go build ./...
go test ./...
```

None of the commands above, `git init` aside, have been run as part of
producing this repository. This is scaffolded, reviewed-by-hand starter
code, not a validated working build.

## What this does NOT prove

This is the most important section in this README, and it applies equally
to every claim made above:

- TouchSign proves that **a specific enrolled FIDO2 hardware key was
  physically touched** at the moment a commit was signed (or, for the
  anomaly detector, that *two* signatures from the same signer were spaced
  far enough apart to plausibly be two separate physical touches).
- TouchSign does **not** prove that the *diff content* of that commit was
  composed by a human, or by that human, or without AI assistance. Someone
  can absolutely paste LLM-generated code into their editor and then sign
  the resulting commit with their own hardware key, entirely normally, and
  TouchSign will report a perfectly valid, perfectly plausible signature.
  Physical presence at signing time and authorship of the content are two
  different claims, and this project only ever makes the first one.
- TouchSign does not defend against a stolen or willingly-shared
  authenticator, a coerced signer, or a contributor who is simply less
  careful about what they sign. See `docs/threat-model.md` for a fuller
  treatment of these limits and what a false positive looks like in
  practice.

If you need a tool that claims to verify *who wrote the code*, this isn't
it, and -- per `docs/adr/0001-why-ssh-signing-not-custom-webauthn.md` --
no tool that claims that convincingly for arbitrary text should be trusted
much further than TouchSign trusts itself here.

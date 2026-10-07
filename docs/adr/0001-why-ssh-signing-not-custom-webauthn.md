# ADR 0001: Build on git's native SSH/FIDO2 commit signing, not a custom WebAuthn/CTAP2 implementation

- Status: Accepted
- Date: 2026-09-27

## Context

TouchSign's premise is "proving a human was physically present" applied to
git workflows: given the flood of low-effort, AI-generated pull requests
maintainers now face, can a repository require *some* signal that a
specific human physically acted at commit time, without requiring video
calls or biometric enrollment?

FIDO2/CTAP2 authenticators (YubiKeys, platform authenticators, etc.) already
solve the "prove physical presence" primitive: a "get assertion" request
with user-presence enforcement will not produce a signature unless a human
touches the device for that specific operation. The open question for this
project was not *whether* to use that primitive, but *how much of the
supporting protocol stack to build ourselves*.

Two paths were considered:

### Option A: Implement WebAuthn/CTAP2 registration and assertion directly

Build a service that speaks CTAP2 (or WebAuthn via a browser ceremony) to
authenticators directly, maintains its own attestation/registration
records, and issues its own notion of a "signed, human-present" event tied
to a git commit.

**Rejected.** This means:

- Re-implementing (or vendoring, but still operating and trusting) a
  security-critical protocol stack: attestation verification, assertion
  signature verification, counter/replay handling, and correct handling of
  the many authenticator quirks that exist in practice. This is exactly the
  kind of "custom crypto" reinvention this portfolio's other projects
  explicitly avoid (see the sibling ADR's "build on audited libraries, not
  custom crypto" reasoning) -- the risk profile of a home-grown CTAP2/WebAuthn
  relying-party implementation is not something a solo project should carry
  when a correct, audited path already exists one layer down.
- Inventing a new key-registry, new revocation flow, and new
  attestation/trust model that developers would need to learn and operate
  *in addition to* git and GitHub -- a second system of record alongside
  the one (git) they already trust for everything else in the repository.
- No natural integration point with existing git/GitHub tooling: commit
  signature verification badges, `git log --show-signature`, branch
  protection's "require signed commits," and every code-review tool that
  already understands git signatures would all need custom shims or would
  simply not apply.

### Option B: Build entirely on git's existing FIDO2-resident-SSH-key signing support (chosen)

Git has supported SSH commit signatures since 2.34, and OpenSSH has
supported FIDO2-resident keys (`ssh-keygen -t ed25519-sk`) for exactly as
long. Setting `gpg.format ssh` and `commit.gpgsign true`, with a
`sk-ssh-ed25519@openssh.com` resident key requiring `verify-required` touch
policy, means:

- `git commit` already refuses to produce a signature without the
  authenticator confirming a physical touch. This is the *exact* guarantee
  Option A was trying to build, delivered for free, already shipped,
  already audited by the OpenSSH and git maintainers and a much larger user
  base than this project could ever provide on its own.
- `git verify-commit` and `git log --show-signature` already verify these
  signatures against an `allowed_signers` file -- also an existing,
  documented git/OpenSSH format, not a new one TouchSign has to invent.
- GitHub, GitLab, and every other major forge already render SSH commit
  signature status natively.

**Accepted.** TouchSign's entire contribution is the layer *above* this
existing mechanism: parsing `git verify-commit` output into structured
data (`internal/verify`), noticing when the *timing* between two supposedly
independent touch-signed commits is physically implausible for a human
(`internal/anomaly` -- the actual novel engineering here), applying a
per-repository policy about which paths require what coverage
(`internal/policy`), and reporting the result back into the PR
(`internal/report`). None of that requires touching a single byte of
CTAP2/WebAuthn wire format.

## Consequences

- TouchSign has a hard dependency on contributors having FIDO2-resident SSH
  keys configured and `gpg.format ssh` set locally. This is a real adoption
  cost, but it is git/OpenSSH's existing cost, not a new one TouchSign
  introduces.
- TouchSign cannot verify anything about *how* the signature was produced
  beyond what git itself reports -- if a future git/OpenSSH release changes
  `verify-commit`'s output format, `internal/verify`'s parsing needs to
  track that. This is treated as an acceptable, well-scoped maintenance
  surface compared to owning protocol-level verification.
- Because the touch guarantee lives entirely in the authenticator and git's
  existing signature verification, TouchSign inherits their limitations
  too -- most importantly, a touch-signed commit proves a specific
  hardware key was touched, not that the diff content was authored by a
  human. See the README's "What this does NOT prove" section and
  `docs/threat-model.md`.
- Keystroke-cadence or typing-biometrics analysis was considered as an
  additional signal and explicitly rejected for this project: it is a weak,
  easily-spoofed signal (trivial to replay or synthesize plausible-looking
  keystroke timing) that would require collecting sensitive behavioral data
  from contributors' editors, for a marginal benefit that doesn't justify
  either the privacy cost or the engineering effort. The commit-timing
  anomaly detector in `internal/anomaly` operates only on data git already
  produces (commit timestamps + verified signer identity) and needs no new
  data collection at all.

// Package verify wraps git's own commit-signature verification commands
// (`git verify-commit` and `git log --show-signature`) rather than
// reimplementing SSH signature verification. Git already knows how to call
// `ssh-keygen -Y verify` under the hood when `gpg.format` is `ssh` and
// `gpg.ssh.allowedSignersFile` points at a registry file (see
// internal/registry) -- TouchSign's job is to run that existing machinery,
// capture its output, and turn it into structured data the policy engine
// and anomaly detector can reason about.
//
// Every function in this package that talks to git does so by shelling out
// via os/exec. Nothing here parses SSH signature packets, CTAP2 assertions,
// or key material directly.
package verify

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// CommitVerification is the structured result of verifying a single
// commit's signature.
type CommitVerification struct {
	// SHA is the full 40 (or 64, for sha256 repos) character commit hash.
	SHA string

	// Signer is the principal git's ssh-signature verification resolved
	// the signature to -- i.e. the left-hand column of the matching
	// allowed_signers line. Empty if verification failed outright.
	Signer string

	// KeyFingerprint is the SHA256 key fingerprint git printed for the
	// signing key (the "SHA256:xxxxx" token `ssh-keygen -Y verify` and
	// `git verify-commit` report), independent of Signer -- useful for
	// detecting a signer's key being swapped out without the principal
	// name changing.
	KeyFingerprint string

	// Verified is true only when git reported a "Good" signature. Any
	// parse failure, missing signature, or explicit "Bad"/"error" result
	// is Verified: false.
	Verified bool

	// SignedAt is the commit's committer timestamp, used as a proxy for
	// "when this signature was produced". Git's ssh-signature format does
	// not carry an independent signing timestamp the way an OpenPGP
	// signature packet can, so TouchSign uses the committer date recorded
	// in the commit object itself. This is what the anomaly detector's
	// timing analysis operates on.
	SignedAt time.Time

	// RawOutput preserves git's original verification output for the
	// commit, for debugging and for inclusion in the JSON report when a
	// verification fails in an unexpected way.
	RawOutput string
}

// Runner abstracts command execution so tests can substitute a fake without
// actually invoking git. The zero value of Verifier uses execRunner, which
// really shells out.
type Runner interface {
	Run(ctx context.Context, dir string, name string, args ...string) (stdout string, stderr string, err error)
}

// execRunner is the real os/exec-backed Runner.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, dir string, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Verifier runs and parses git's commit signature verification.
type Verifier struct {
	// Runner defaults to shelling out to the real `git` binary. Tests
	// inject a fake to avoid executing anything.
	Runner Runner
}

// NewVerifier returns a Verifier backed by the real git CLI.
func NewVerifier() *Verifier {
	return &Verifier{Runner: execRunner{}}
}

// goodSignatureRE matches the line git prints (via `ssh-keygen -Y verify`)
// for a successfully verified SSH commit signature, e.g.:
//
//	Good "git" signature for alice@example.com with ED25519 key SHA256:abc123...
//
// or, for a FIDO2-resident key:
//
//	Good "git" signature for alice@example.com with SK-ED25519 key SHA256:abc123...
var goodSignatureRE = regexp.MustCompile(`Good "git" signature for ([^\s]+) with [\w-]+ key (SHA256:\S+)`)

// badSignatureRE matches git's failure phrasing so we can distinguish "no
// signature at all" from "signature present but invalid/untrusted".
var badSignatureRE = regexp.MustCompile(`(?i)(Bad "git" signature|No signature|error: |cannot verify)`)

// VerifyCommit verifies a single commit's signature by shelling out to
// `git verify-commit --raw <sha>` and `git log -1` for commit metadata, then
// parsing the combined output into a CommitVerification.
func (v *Verifier) VerifyCommit(ctx context.Context, repoPath, sha string) (CommitVerification, error) {
	runner := v.Runner
	if runner == nil {
		runner = execRunner{}
	}

	result := CommitVerification{SHA: sha}

	// 1. Commit metadata: full SHA + committer date (ISO 8601), used as the
	// SignedAt proxy discussed in the CommitVerification doc comment.
	metaOut, metaErr, err := runner.Run(ctx, repoPath, "git", "log", "-1", "--format=%H%x1f%cI", sha)
	if err != nil {
		return result, fmt.Errorf("verify: git log for %s: %w (stderr: %s)", sha, err, strings.TrimSpace(metaErr))
	}
	fields := strings.SplitN(strings.TrimSpace(metaOut), "\x1f", 2)
	if len(fields) == 2 {
		result.SHA = fields[0]
		if t, perr := time.Parse(time.RFC3339, fields[1]); perr == nil {
			result.SignedAt = t
		}
	}

	// 2. Signature verification itself. `--raw` gives the most
	// machine-stable status lines. Note git writes this to stderr, not
	// stdout, regardless of exit code.
	_, sigErr, verifyErr := runner.Run(ctx, repoPath, "git", "verify-commit", "--raw", sha)
	result.RawOutput = sigErr

	if m := goodSignatureRE.FindStringSubmatch(sigErr); m != nil {
		result.Verified = true
		result.Signer = m[1]
		result.KeyFingerprint = m[2]
		return result, nil
	}

	// Not matched as good. Record whatever git told us; a non-nil
	// verifyErr here is expected (git verify-commit exits non-zero for an
	// unsigned or bad-signature commit) and is not itself a Go-level
	// error -- it's exactly the "unverified" case we want to report.
	result.Verified = false
	if !badSignatureRE.MatchString(sigErr) && verifyErr == nil {
		// Verification claimed success but our regex didn't match the
		// expected format -- surface this as a real error since it likely
		// means git's output format changed underneath us.
		return result, fmt.Errorf("verify: unrecognized git verify-commit output for %s: %q", sha, sigErr)
	}
	return result, nil
}

// VerifyRange verifies every commit reachable from headSHA but not from
// baseSHA -- i.e. exactly the commits a pull request introduces -- which is
// what a CI check invoked on a PR would call. Commits are returned oldest
// first (matching `git rev-list --reverse`).
func (v *Verifier) VerifyRange(ctx context.Context, repoPath, baseSHA, headSHA string) ([]CommitVerification, error) {
	runner := v.Runner
	if runner == nil {
		runner = execRunner{}
	}

	revRange := fmt.Sprintf("%s..%s", baseSHA, headSHA)
	stdout, stderr, err := runner.Run(ctx, repoPath, "git", "rev-list", "--reverse", revRange)
	if err != nil {
		return nil, fmt.Errorf("verify: git rev-list %s: %w (stderr: %s)", revRange, err, strings.TrimSpace(stderr))
	}

	var shas []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			shas = append(shas, line)
		}
	}

	results := make([]CommitVerification, 0, len(shas))
	for _, sha := range shas {
		cv, err := v.VerifyCommit(ctx, repoPath, sha)
		if err != nil {
			return results, fmt.Errorf("verify: commit %s: %w", sha, err)
		}
		results = append(results, cv)
	}
	return results, nil
}

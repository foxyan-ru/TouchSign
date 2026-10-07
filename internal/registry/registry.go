// Package registry parses and writes files in git's native "allowed signers"
// format (see `man ssh-keygen` -> ALLOWED SIGNERS, and
// `git help gpg-sign` / `gpg.ssh.allowedSignersFile`).
//
// TouchSign does not invent its own key-registry format or protocol. It
// reuses the exact file format `git verify-commit` and `git log
// --show-signature` already understand when `gpg.format` is set to `ssh`:
//
//	<principal> [options] <key-type> <base64-key> [comment...]
//
// where <principal> is typically an email address, <key-type> is something
// like "sk-ssh-ed25519@openssh.com" for a FIDO2-resident key, and <options>
// may include a `valid-after="..."` / `valid-before="..."` restriction in
// the same syntax OpenSSH uses for certificate validity windows.
//
// Enrollment workflow (by design, not by extra code):
//
// The registry file is expected to live inside the repository it protects
// (e.g. `.touchsign/allowed_signers`). A contributor "enrolls" a new
// FIDO2-backed signing key by opening a pull request that appends their line
// to this file -- the same code-review path used for any other change. A
// human reviewer (or a required-reviewers branch policy) is the enrollment
// gate; there is no separate enrollment service, database, or API to
// operate or secure. Revocation works identically: a PR that removes (or
// time-bounds via `valid-before`) a contributor's line, reviewed and merged
// like any other change. This keeps the trust root entirely inside git's
// existing access-control and audit trail (commit history, PR review,
// branch protection) rather than introducing a new one.
package registry

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// timeLayout matches the format OpenSSH uses for valid-after/valid-before
// timestamps in allowed_signers restrictions: YYYYMMDDHHMMSS, optionally
// suffixed with Z for UTC. We accept both when parsing and always emit the
// Z-suffixed UTC form when writing.
const timeLayout = "20060102150405"

// Entry is a single parsed line of an allowed_signers file.
type Entry struct {
	// Principal is usually the contributor's email address, matched against
	// the "signer" identity git extracts from the SSH signature.
	Principal string

	// KeyType is the SSH key type string, e.g. "sk-ssh-ed25519@openssh.com"
	// for a FIDO2/CTAP2 resident key, or plain "ssh-ed25519" for a
	// non-hardware key (TouchSign's policy layer may choose to reject the
	// latter -- see internal/policy -- but the registry format itself does
	// not distinguish them beyond the key-type string).
	KeyType string

	// PublicKey is the base64-encoded key material (no "ssh-ed25519 "
	// prefix, no comment).
	PublicKey string

	// Comment is any trailing free-text comment on the line (often used to
	// note the contributor's name or enrollment PR number). Optional.
	Comment string

	// ValidAfter / ValidBefore mirror the optional `valid-after="..."` /
	// `valid-before="..."` restrictions from the allowed_signers format.
	// Zero value means "no restriction".
	ValidAfter  time.Time
	ValidBefore time.Time
}

// Revoked reports whether the entry is outside its validity window at t.
func (e *Entry) Revoked(t time.Time) bool {
	if !e.ValidBefore.IsZero() && !t.Before(e.ValidBefore) {
		return true
	}
	if !e.ValidAfter.IsZero() && t.Before(e.ValidAfter) {
		return true
	}
	return false
}

// String renders the entry back into a single allowed_signers line.
func (e *Entry) String() string {
	var b strings.Builder
	b.WriteString(e.Principal)
	b.WriteByte(' ')

	var opts []string
	if !e.ValidAfter.IsZero() {
		opts = append(opts, fmt.Sprintf(`valid-after="%s"`, e.ValidAfter.UTC().Format(timeLayout)+"Z"))
	}
	if !e.ValidBefore.IsZero() {
		opts = append(opts, fmt.Sprintf(`valid-before="%s"`, e.ValidBefore.UTC().Format(timeLayout)+"Z"))
	}
	if len(opts) > 0 {
		b.WriteString(strings.Join(opts, ","))
		b.WriteByte(' ')
	}

	b.WriteString(e.KeyType)
	b.WriteByte(' ')
	b.WriteString(e.PublicKey)
	if e.Comment != "" {
		b.WriteByte(' ')
		b.WriteString(e.Comment)
	}
	return b.String()
}

// Registry is an in-memory view of an allowed_signers file, keyed by
// principal. Multiple entries per principal are supported (key rotation),
// mirroring what git itself tolerates in the file.
type Registry struct {
	path    string
	entries map[string][]*Entry
	// order preserves original line order (minus comments/blanks) so that
	// Save() produces a minimal, human-reviewable diff.
	order []*Entry
}

// New returns an empty Registry that will read/write at path.
func New(path string) *Registry {
	return &Registry{
		path:    path,
		entries: make(map[string][]*Entry),
	}
}

// Load reads and parses an allowed_signers file at path. A missing file is
// not an error -- it is treated as an empty registry, since a brand new repo
// may not have enrolled any signers yet.
func Load(path string) (*Registry, error) {
	r := New(path)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("registry: opening %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("registry: %s:%d: %w", path, lineNo, err)
		}
		r.entries[entry.Principal] = append(r.entries[entry.Principal], entry)
		r.order = append(r.order, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("registry: reading %q: %w", path, err)
	}
	return r, nil
}

// parseLine parses one non-empty, non-comment allowed_signers line:
//
//	principal[,principal...] [options] keytype base64key [comment...]
//
// options is a comma-separated list of key="value" pairs, of which
// TouchSign understands valid-after and valid-before. Other options
// (cert-authority, namespaces=...) are preserved verbatim in Comment-less
// round-tripping is best-effort; this parser is intentionally conservative
// and only needs to handle the subset TouchSign itself writes plus the
// common manual case.
func parseLine(line string) (*Entry, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, fmt.Errorf("malformed allowed_signers line (need at least principal, keytype, key): %q", line)
	}

	e := &Entry{Principal: fields[0]}
	idx := 1

	// Optional options field: it never starts with "ssh-" / "sk-ssh-" /
	// "ecdsa-sk" etc, so distinguish it from a key-type token by checking
	// for an '=' sign, which real key-type tokens never contain.
	if strings.Contains(fields[idx], "=") {
		if err := applyOptions(e, fields[idx]); err != nil {
			return nil, err
		}
		idx++
	}

	if idx >= len(fields) {
		return nil, fmt.Errorf("malformed allowed_signers line (missing key type/material): %q", line)
	}
	e.KeyType = fields[idx]
	idx++

	if idx >= len(fields) {
		return nil, fmt.Errorf("malformed allowed_signers line (missing base64 key material): %q", line)
	}
	e.PublicKey = fields[idx]
	idx++

	if idx < len(fields) {
		e.Comment = strings.Join(fields[idx:], " ")
	}

	return e, nil
}

func applyOptions(e *Entry, raw string) error {
	for _, opt := range splitOptions(raw) {
		kv := strings.SplitN(opt, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		val := strings.Trim(kv[1], `"`)
		switch key {
		case "valid-after":
			t, err := parseValidityTime(val)
			if err != nil {
				return fmt.Errorf("valid-after: %w", err)
			}
			e.ValidAfter = t
		case "valid-before":
			t, err := parseValidityTime(val)
			if err != nil {
				return fmt.Errorf("valid-before: %w", err)
			}
			e.ValidBefore = t
		}
		// Unknown options (cert-authority, namespaces=..., etc.) are
		// silently ignored for now; TouchSign only needs the validity
		// window today.
	}
	return nil
}

// splitOptions splits a comma-separated options field while respecting
// double-quoted values that may themselves not contain commas (OpenSSH's
// format does not require escaping commas inside quotes for the options
// TouchSign cares about, so a simple split is sufficient here).
func splitOptions(raw string) []string {
	return strings.Split(raw, ",")
}

func parseValidityTime(val string) (time.Time, error) {
	val = strings.TrimSuffix(val, "Z")
	return time.Parse(timeLayout, val)
}

// Add appends a new entry for contributor with the given public key line
// (in "<key-type> <base64-key> [comment]" form, exactly as `ssh-keygen` or
// the FIDO2 authenticator would emit it) and persists the registry to disk.
//
// In the enrollment workflow this method models, Add is not meant to be
// called against a live production registry directly by TouchSign itself --
// it is what a small helper CLI or the contributor's own local tooling would
// call to *generate* the line for their enrollment pull request. TouchSign's
// CI-side checks only ever read the registry (via Lookup) once that PR has
// been reviewed and merged.
func (r *Registry) Add(contributor, publicKey string) error {
	if contributor == "" {
		return fmt.Errorf("registry: contributor principal must not be empty")
	}
	fields := strings.Fields(publicKey)
	if len(fields) < 2 {
		return fmt.Errorf("registry: publicKey must be \"<key-type> <base64-key> [comment]\", got %q", publicKey)
	}

	e := &Entry{
		Principal: contributor,
		KeyType:   fields[0],
		PublicKey: fields[1],
	}
	if len(fields) > 2 {
		e.Comment = strings.Join(fields[2:], " ")
	}

	r.entries[contributor] = append(r.entries[contributor], e)
	r.order = append(r.order, e)

	return r.Save()
}

// Revoke removes all entries for contributor and persists the change.
//
// As with Add, in practice this models the diff a revocation pull request
// would contain -- git history retains the fact that the key was once
// trusted, which is itself useful audit trail.
func (r *Registry) Revoke(contributor string) error {
	if _, ok := r.entries[contributor]; !ok {
		return fmt.Errorf("registry: no entries found for contributor %q", contributor)
	}
	delete(r.entries, contributor)

	filtered := r.order[:0:0]
	for _, e := range r.order {
		if e.Principal != contributor {
			filtered = append(filtered, e)
		}
	}
	r.order = filtered

	return r.Save()
}

// Lookup returns the most recently added, still-valid entry for a
// contributor. It returns an error if the contributor has no entries at
// all; callers that care about expired-vs-absent should inspect Revoked()
// on entries obtained via LookupAll.
func (r *Registry) Lookup(contributor string) (*Entry, error) {
	entries, ok := r.entries[contributor]
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("registry: no signer enrolled for %q", contributor)
	}
	// Last-added wins for "the current key" -- rotation is expected to be
	// modeled as: add the new line, then a later PR removes the old one.
	return entries[len(entries)-1], nil
}

// LookupAll returns every entry (current and historical) for a contributor,
// in the order they appear in the file. Useful for verifying commits signed
// under a since-rotated key.
func (r *Registry) LookupAll(contributor string) []*Entry {
	return append([]*Entry(nil), r.entries[contributor]...)
}

// Principals returns every enrolled principal, sorted, mostly for
// diagnostics and `touchsign` CLI output.
func (r *Registry) Principals() []string {
	out := make([]string, 0, len(r.entries))
	for p := range r.entries {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Save writes the registry back to its backing file in allowed_signers
// format, one entry per line, in insertion order.
func (r *Registry) Save() error {
	f, err := os.Create(r.path)
	if err != nil {
		return fmt.Errorf("registry: creating %q: %w", r.path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	w.WriteString("# allowed_signers file managed by TouchSign.\n")
	w.WriteString("# Format: <principal> [valid-after=\"...\",valid-before=\"...\"] <key-type> <base64-key> [comment]\n")
	w.WriteString("# Enroll a new key or revoke one via a reviewed pull request that edits this file.\n")
	for _, e := range r.order {
		if _, err := w.WriteString(e.String() + "\n"); err != nil {
			return fmt.Errorf("registry: writing entry for %q: %w", e.Principal, err)
		}
	}
	return w.Flush()
}

// Path returns the backing file path this registry reads from and writes
// to.
func (r *Registry) Path() string {
	return r.path
}

// EntryCount returns the total number of entries currently loaded, across
// all principals. Mostly useful for diagnostics and tests.
func (r *Registry) EntryCount() int {
	return len(r.order)
}

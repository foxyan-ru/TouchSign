// Package policy loads a repository's TouchSign policy file (YAML) and
// evaluates it against a pull request's changed files, commit signature
// verifications, and detected anomalies.
//
// The policy format intentionally stays small and declarative: a list of
// path-glob rules, each specifying what fraction of touched files under
// that glob must be covered by verified, human-touch signatures, and
// whether a detected anomaly should hard-block the rule outright. See
// docs/policy-example.yaml for a worked example.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/mstone/touchsign/internal/anomaly"
	"github.com/mstone/touchsign/internal/verify"
)

// Rule is a single policy rule matched against changed files by glob.
type Rule struct {
	// PathGlob is matched against each changed file's repo-relative path
	// using path/filepath.Match semantics (extended with "**" support --
	// see matchGlob below, since filepath.Match alone does not support
	// multi-segment "**" wildcards).
	PathGlob string `yaml:"path_glob"`

	// RequireCoverage is the minimum fraction (0.0-1.0) of files matching
	// PathGlob that must appear in a commit whose signature verified
	// successfully. 1.0 means every matching file's commit(s) must carry a
	// verified touch-signature; 0.0 effectively disables the rule's
	// coverage requirement (useful for e.g. docs/**).
	RequireCoverage float64 `yaml:"require_coverage"`

	// BlockOnAnomaly, when true, fails this rule outright if ANY anomaly
	// was detected in the verification set for the PR, regardless of
	// coverage -- intended for the most sensitive paths (e.g.
	// payments/core/**) where an implausible signing cadence should never
	// be waved through even at 100% nominal coverage.
	BlockOnAnomaly bool `yaml:"block_on_anomaly"`
}

// Policy is the top-level YAML document shape.
type Policy struct {
	Rules []Rule `yaml:"rules"`
}

// Load reads and parses a policy YAML file from path.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: reading %q: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parsing %q: %w", path, err)
	}

	for i, r := range p.Rules {
		if r.PathGlob == "" {
			return nil, fmt.Errorf("policy: rule %d in %q has an empty path_glob", i, path)
		}
		if r.RequireCoverage < 0 || r.RequireCoverage > 1 {
			return nil, fmt.Errorf("policy: rule %d (%s) has require_coverage %.2f, must be between 0.0 and 1.0", i, r.PathGlob, r.RequireCoverage)
		}
	}

	return &p, nil
}

// PolicyResult is the outcome of evaluating a policy against a PR.
type PolicyResult struct {
	// Allowed is true only if every rule that matched at least one changed
	// file passed its coverage requirement and, where applicable, its
	// anomaly gate.
	Allowed bool

	// Violations is a human-readable list of every rule failure, suitable
	// for direct inclusion in a PR comment or CI log.
	Violations []string

	// RuleCoverage records the computed coverage fraction per matched
	// path_glob, for reporting purposes.
	RuleCoverage map[string]float64
}

// Evaluate checks changedFiles against rules, using verifications to
// determine which files were "covered" by a verified signature and
// anomalies to apply any block_on_anomaly gates.
//
// A changed file is considered "covered" if at least one commit in
// verifications that is Verified == true is associated with that file.
// Since git's plumbing does not directly give us a commit-to-file mapping
// at this layer (that comes from `git diff-tree` / `git show --name-only`
// per commit, deliberately left to the caller so this package stays a pure
// function of its inputs), Evaluate accepts a pre-computed
// fileToCommits map via EvaluateWithFileMap. Evaluate itself provides the
// simpler, common-case semantics: coverage is computed against ALL
// verifications passed in, i.e. "were the changes in this PR, taken as a
// whole, signed by verified signatures" -- appropriate for repos that
// squash-merge or otherwise don't need per-file attribution.
func Evaluate(changedFiles []string, verifications []verify.CommitVerification, anomalies []anomaly.Anomaly, rules []Rule) PolicyResult {
	verifiedCount := 0
	for _, v := range verifications {
		if v.Verified {
			verifiedCount++
		}
	}
	overallCoverage := 1.0
	if len(verifications) > 0 {
		overallCoverage = float64(verifiedCount) / float64(len(verifications))
	} else if len(changedFiles) > 0 {
		// Files changed but nothing to verify at all (e.g. no commits
		// resolved) -- treat as zero coverage rather than vacuously "fine".
		overallCoverage = 0.0
	}

	hasAnomaly := len(anomalies) > 0

	result := PolicyResult{
		Allowed:      true,
		RuleCoverage: make(map[string]float64),
	}

	for _, rule := range rules {
		matched := matchedFiles(changedFiles, rule.PathGlob)
		if len(matched) == 0 {
			// Rule doesn't apply to this PR's changed files -- not a
			// violation, just irrelevant.
			continue
		}

		result.RuleCoverage[rule.PathGlob] = overallCoverage

		if overallCoverage+1e-9 < rule.RequireCoverage {
			result.Allowed = false
			result.Violations = append(result.Violations, fmt.Sprintf(
				"%s: coverage %.0f%% is below required %.0f%% (%d/%d matched files under signed commits)",
				rule.PathGlob, overallCoverage*100, rule.RequireCoverage*100, verifiedCount, len(verifications),
			))
		}

		if rule.BlockOnAnomaly && hasAnomaly {
			result.Allowed = false
			result.Violations = append(result.Violations, fmt.Sprintf(
				"%s: blocked due to %d detected signing-cadence anomal(y/ies) (block_on_anomaly=true)",
				rule.PathGlob, len(anomalies),
			))
		}
	}

	sort.Strings(result.Violations)
	return result
}

// matchedFiles returns the subset of files matching glob.
func matchedFiles(files []string, glob string) []string {
	var out []string
	for _, f := range files {
		if matchGlob(glob, f) {
			out = append(out, f)
		}
	}
	return out
}

// matchGlob extends path/filepath.Match with basic "**" support (matching
// across directory separators), since the standard library's Match treats
// "*" as not crossing "/" boundaries and has no concept of "**" at all.
// This is a small, deliberately simple implementation -- it is not a full
// gitignore-style matcher, just enough for policy files like
// "payments/core/**" or "**/*.sql".
func matchGlob(pattern, name string) bool {
	// Normalize to forward slashes; policy files and git both use "/".
	pattern = filepath.ToSlash(pattern)
	name = filepath.ToSlash(name)

	if pattern == name {
		return true
	}

	// Fast path: no "**" at all, defer straight to filepath.Match per
	// path segment-safe pattern (works fine for single-level "*" globs
	// like "*.go" applied to a bare filename, and for exact-ish patterns
	// without "**").
	if !containsDoubleStar(pattern) {
		ok, err := filepath.Match(pattern, name)
		return err == nil && ok
	}

	return matchDoubleStar(pattern, name)
}

func containsDoubleStar(pattern string) bool {
	for i := 0; i+1 < len(pattern); i++ {
		if pattern[i] == '*' && pattern[i+1] == '*' {
			return true
		}
	}
	return false
}

// matchDoubleStar implements "**" as "zero or more path segments" by
// splitting the pattern on "/**" segments and requiring each literal chunk
// to appear in order within name, anchored appropriately at the start/end.
//
// Supported shapes (sufficient for realistic policy files):
//
//	"payments/core/**"   -> prefix match on "payments/core/"
//	"**/*.sql"           -> suffix match on "*.sql" at any depth
//	"a/**/b"             -> "a/" ... "/b" with anything (incl. nothing) between
func matchDoubleStar(pattern, name string) bool {
	switch {
	case len(pattern) >= 3 && pattern[len(pattern)-3:] == "/**":
		prefix := pattern[:len(pattern)-2] // keep trailing "/"
		return len(name) >= len(prefix) && name[:len(prefix)] == prefix
	case len(pattern) >= 3 && pattern[:3] == "**/":
		suffix := pattern[3:]
		ok, err := filepath.Match(suffix, filepath.Base(name))
		if err == nil && ok {
			return true
		}
		// Also allow the suffix pattern to match against the full
		// remaining path for patterns like "**/vendor/*.go".
		ok, err = filepath.Match("*/"+suffix, name)
		return err == nil && ok
	default:
		// A "**" appearing in the middle of the pattern: split around the
		// first occurrence and require both halves to match as
		// prefix/suffix, with anything (including "/") in between.
		idx := indexDoubleStar(pattern)
		prefix := pattern[:idx]
		suffix := pattern[idx+2:]
		return len(name) >= len(prefix)+len(suffix) &&
			name[:len(prefix)] == prefix &&
			name[len(name)-len(suffix):] == suffix
	}
}

func indexDoubleStar(pattern string) int {
	for i := 0; i+1 < len(pattern); i++ {
		if pattern[i] == '*' && pattern[i+1] == '*' {
			return i
		}
	}
	return -1
}

// Package report assembles TouchSign's verification, anomaly, and policy
// results into a single structured Report, renders a human-readable
// summary for CI logs, and serializes the JSON form that action.yml wires
// up to be posted back to the pull request as a comment (see github.go).
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mstone/touchsign/internal/anomaly"
	"github.com/mstone/touchsign/internal/policy"
	"github.com/mstone/touchsign/internal/verify"
)

// Report is the full output of a `touchsign check` run.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	RepoPath    string    `json:"repo_path"`
	BaseSHA     string    `json:"base_sha"`
	HeadSHA     string    `json:"head_sha"`

	Commits   []verify.CommitVerification `json:"commits"`
	Anomalies []anomaly.Anomaly           `json:"anomalies"`
	Policy    policy.PolicyResult         `json:"policy"`

	// CoveragePercent is the overall verified-signature coverage across
	// Commits, expressed 0-100 for readability in the JSON report.
	CoveragePercent float64 `json:"coverage_percent"`

	// Allowed mirrors Policy.Allowed at the top level so downstream
	// consumers (e.g. a shell script checking `jq .allowed`) don't need to
	// reach into the nested policy object.
	Allowed bool `json:"allowed"`
}

// Build assembles a Report from the outputs of the verify, anomaly, and
// policy packages. It performs no I/O itself.
func Build(repoPath, baseSHA, headSHA string, commits []verify.CommitVerification, anomalies []anomaly.Anomaly, policyResult policy.PolicyResult) Report {
	verifiedCount := 0
	for _, c := range commits {
		if c.Verified {
			verifiedCount++
		}
	}
	coverage := 100.0
	if len(commits) > 0 {
		coverage = 100.0 * float64(verifiedCount) / float64(len(commits))
	}

	return Report{
		GeneratedAt:     time.Now().UTC(),
		RepoPath:        repoPath,
		BaseSHA:         baseSHA,
		HeadSHA:         headSHA,
		Commits:         commits,
		Anomalies:       anomalies,
		Policy:          policyResult,
		CoveragePercent: coverage,
		Allowed:         policyResult.Allowed,
	}
}

// WriteJSON writes the report as indented JSON to path.
func (r Report) WriteJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshaling JSON: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("report: writing %q: %w", path, err)
	}
	return nil
}

// JSON returns the report as an indented JSON string, e.g. for posting as a
// PR comment body without an intermediate file.
func (r Report) JSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("report: marshaling JSON: %w", err)
	}
	return string(data), nil
}

// Summary renders a compact, human-readable report suitable for a CI log or
// as the body of a PR comment (see github.go, which wraps this in a little
// extra Markdown framing).
func (r Report) Summary() string {
	var b strings.Builder

	status := "PASS"
	if !r.Allowed {
		status = "FAIL"
	}

	fmt.Fprintf(&b, "TouchSign check: %s\n", status)
	fmt.Fprintf(&b, "Range: %s..%s\n", shortSHA(r.BaseSHA), shortSHA(r.HeadSHA))
	fmt.Fprintf(&b, "Commits checked: %d\n", len(r.Commits))
	fmt.Fprintf(&b, "Signature coverage: %.1f%%\n", r.CoveragePercent)

	if len(r.Anomalies) == 0 {
		b.WriteString("Timing anomalies: none\n")
	} else {
		fmt.Fprintf(&b, "Timing anomalies: %d\n", len(r.Anomalies))
		for _, a := range r.Anomalies {
			fmt.Fprintf(&b, "  - %s: %s and %s signed %dms apart by %s (below plausible human floor)\n",
				a.Type, shortSHA(a.Commits[0]), shortSHA(a.Commits[1]), a.GapMs, a.Signer)
		}
	}

	if len(r.Policy.Violations) == 0 {
		b.WriteString("Policy violations: none\n")
	} else {
		fmt.Fprintf(&b, "Policy violations: %d\n", len(r.Policy.Violations))
		for _, v := range r.Policy.Violations {
			fmt.Fprintf(&b, "  - %s\n", v)
		}
	}

	for _, c := range r.Commits {
		mark := "unsigned/invalid"
		if c.Verified {
			mark = "verified: " + c.Signer
		}
		fmt.Fprintf(&b, "  commit %s: %s\n", shortSHA(c.SHA), mark)
	}

	return b.String()
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// Package anomaly implements TouchSign's core insight: a FIDO2
// touch-required signing key has a physical human-reaction-time floor.
//
// Every signature produced by a `sk-ssh-ed25519@openssh.com` (or
// `sk-ecdsa-sha2-nistp256@openssh.com`) resident key with "user presence"
// enforced requires a human to physically touch the authenticator for that
// specific signing operation. A human cannot physically press a security
// key twice, for two genuinely separate commits, faster than roughly
// 300-500ms apart -- that is simply how fast a person can react and move a
// finger. If two commits attributed to the *same* signer are timestamped
// closer together than that floor allows, something other than "a human
// touched a key twice" produced them: a scripted commit-and-sign loop
// replaying a cached assertion, clock manipulation, commit timestamp
// forgery, or some other process that isn't an individual human physically
// present at the keyboard for each commit.
//
// This package does not, and cannot, prove that the *diff content* of a
// commit was human-written -- see the repository README's "What this does
// NOT prove" section. It only flags signing *cadence* that is physically
// implausible for a single human operator.
package anomaly

import (
	"sort"

	"github.com/mstone/touchsign/internal/verify"
)

// DefaultMinPlausibleGapMs is TouchSign's default floor for the minimum
// time between two touch-required signature operations by the same signer.
// 300ms is a deliberately conservative (i.e. permissive) lower bound on
// human reaction + finger-movement time; it favors false negatives (missing
// a genuinely-too-fast pair) over false positives (flagging a legitimate
// fast-but-human pair). Policy files can tune this per-repository via
// internal/policy.
const DefaultMinPlausibleGapMs = 300

// AnomalyType identifies the kind of anomaly detected. Currently only one
// type is implemented; the type is still modeled as a string (rather than a
// bare bool) so additional detectors can be added later (e.g. signer/key
// mismatch, out-of-order commit timestamps) without changing the shape
// callers depend on.
const TypeImplausibleSigningCadence = "implausible_signing_cadence"

// Anomaly describes one detected irregularity between two commits.
type Anomaly struct {
	// Type identifies the detector that raised this anomaly.
	Type string

	// Commits holds the SHAs involved, in chronological order. For
	// TypeImplausibleSigningCadence this is always exactly two SHAs: the
	// earlier commit and the later commit in the offending pair.
	Commits []string

	// GapMs is the observed gap between the two commits' SignedAt
	// timestamps, in milliseconds. Always >= 0 and always < the
	// minPlausibleGapMs threshold that was in effect when this anomaly was
	// raised.
	GapMs int64

	// Signer is the shared signer principal both commits verified against.
	Signer string
}

// DetectTimingAnomalies inspects a slice of verified commits and flags any
// pair of CONSECUTIVE commits from the SAME signer whose signing timestamps
// are closer together than minPlausibleGapMs allows.
//
// "Consecutive" here means adjacent once the input is sorted by SignedAt and
// grouped by signer -- i.e. we compare each signer's own commits against
// each other in time order, not every possible pair in the whole list. Two
// different signers acting within the same window is expected and normal
// (two different physical people can absolutely commit within the same
// second) and must never be flagged; the floor is a per-signer physical
// constraint, not a repository-wide rate limit.
//
// Unverified commits (Verified == false) and commits with a zero SignedAt
// are ignored entirely -- there is nothing timing-meaningful to compare for
// a signature that didn't validate in the first place.
//
// The input order is not assumed to be sorted; DetectTimingAnomalies sorts
// a local copy before analysis, so callers can pass verifier output
// directly (e.g. from Verifier.VerifyRange, which returns oldest-first, but
// also anything else).
func DetectTimingAnomalies(verifications []verify.CommitVerification, minPlausibleGapMs int) []Anomaly {
	if minPlausibleGapMs <= 0 {
		minPlausibleGapMs = DefaultMinPlausibleGapMs
	}

	// Group verified, timestamped commits by signer.
	bySigner := make(map[string][]verify.CommitVerification)
	for _, v := range verifications {
		if !v.Verified || v.Signer == "" || v.SignedAt.IsZero() {
			continue
		}
		bySigner[v.Signer] = append(bySigner[v.Signer], v)
	}

	var anomalies []Anomaly
	threshold := int64(minPlausibleGapMs)

	for signer, commits := range bySigner {
		sort.Slice(commits, func(i, j int) bool {
			return commits[i].SignedAt.Before(commits[j].SignedAt)
		})

		for i := 1; i < len(commits); i++ {
			prev := commits[i-1]
			curr := commits[i]

			gap := curr.SignedAt.Sub(prev.SignedAt).Milliseconds()
			if gap < 0 {
				// Should not happen given the sort above, but guard
				// against equal/duplicate timestamps producing a
				// meaningless negative gap from clock skew in test data.
				gap = -gap
			}

			if gap < threshold {
				anomalies = append(anomalies, Anomaly{
					Type:    TypeImplausibleSigningCadence,
					Commits: []string{prev.SHA, curr.SHA},
					GapMs:   gap,
					Signer:  signer,
				})
			}
		}
	}

	// Sort results for deterministic output (map iteration above is
	// unordered): by signer, then by the first commit SHA in the pair.
	sort.Slice(anomalies, func(i, j int) bool {
		if anomalies[i].Signer != anomalies[j].Signer {
			return anomalies[i].Signer < anomalies[j].Signer
		}
		return anomalies[i].Commits[0] < anomalies[j].Commits[0]
	})

	return anomalies
}

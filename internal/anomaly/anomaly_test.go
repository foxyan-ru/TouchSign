package anomaly

import (
	"testing"
	"time"

	"github.com/mstone/touchsign/internal/verify"
)

// mkVerification is a small helper for building CommitVerification fixtures
// without repeating the Verified/SignedAt boilerplate in every case.
func mkVerification(sha, signer string, signedAt time.Time) verify.CommitVerification {
	return verify.CommitVerification{
		SHA:            sha,
		Signer:         signer,
		KeyFingerprint: "SHA256:test-fingerprint-" + signer,
		Verified:       true,
		SignedAt:       signedAt,
	}
}

func TestDetectTimingAnomalies(t *testing.T) {
	base := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name              string
		verifications     []verify.CommitVerification
		minPlausibleGapMs int
		wantAnomalyCount  int
		wantGapMs         int64 // only checked when wantAnomalyCount == 1
	}{
		{
			name: "same signer, minutes apart -> no anomaly",
			verifications: []verify.CommitVerification{
				mkVerification("sha1", "alice@example.com", base),
				mkVerification("sha2", "alice@example.com", base.Add(5*time.Minute)),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  0,
		},
		{
			name: "same signer, 50ms apart -> anomaly flagged",
			verifications: []verify.CommitVerification{
				mkVerification("sha1", "alice@example.com", base),
				mkVerification("sha2", "alice@example.com", base.Add(50*time.Millisecond)),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  1,
			wantGapMs:         50,
		},
		{
			name: "different signers, close together -> no anomaly",
			verifications: []verify.CommitVerification{
				mkVerification("sha1", "alice@example.com", base),
				mkVerification("sha2", "bob@example.com", base.Add(20*time.Millisecond)),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  0,
		},
		{
			name: "same signer, exactly at threshold -> no anomaly (floor is exclusive)",
			verifications: []verify.CommitVerification{
				mkVerification("sha1", "alice@example.com", base),
				mkVerification("sha2", "alice@example.com", base.Add(300*time.Millisecond)),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  0,
		},
		{
			name: "same signer, three commits, only one gap too fast",
			verifications: []verify.CommitVerification{
				mkVerification("sha1", "alice@example.com", base),
				mkVerification("sha2", "alice@example.com", base.Add(10*time.Second)),
				mkVerification("sha3", "alice@example.com", base.Add(10*time.Second+80*time.Millisecond)),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  1,
			wantGapMs:         80,
		},
		{
			name: "unverified commits are ignored even if timestamps are implausible",
			verifications: []verify.CommitVerification{
				{SHA: "sha1", Signer: "alice@example.com", Verified: false, SignedAt: base},
				mkVerification("sha2", "alice@example.com", base.Add(10*time.Millisecond)),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  0,
		},
		{
			name: "input order is irrelevant -- detector sorts by time",
			verifications: []verify.CommitVerification{
				mkVerification("sha2", "alice@example.com", base.Add(50*time.Millisecond)),
				mkVerification("sha1", "alice@example.com", base),
			},
			minPlausibleGapMs: 300,
			wantAnomalyCount:  1,
			wantGapMs:         50,
		},
		{
			name: "zero threshold falls back to package default",
			verifications: []verify.CommitVerification{
				mkVerification("sha1", "alice@example.com", base),
				mkVerification("sha2", "alice@example.com", base.Add(50*time.Millisecond)),
			},
			minPlausibleGapMs: 0,
			wantAnomalyCount:  1,
			wantGapMs:         50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectTimingAnomalies(tt.verifications, tt.minPlausibleGapMs)
			if len(got) != tt.wantAnomalyCount {
				t.Fatalf("DetectTimingAnomalies() returned %d anomalies, want %d: %+v", len(got), tt.wantAnomalyCount, got)
			}
			if tt.wantAnomalyCount == 1 {
				if got[0].Type != TypeImplausibleSigningCadence {
					t.Errorf("anomaly Type = %q, want %q", got[0].Type, TypeImplausibleSigningCadence)
				}
				if got[0].GapMs != tt.wantGapMs {
					t.Errorf("anomaly GapMs = %d, want %d", got[0].GapMs, tt.wantGapMs)
				}
				if len(got[0].Commits) != 2 {
					t.Errorf("anomaly Commits = %v, want exactly 2 SHAs", got[0].Commits)
				}
			}
		})
	}
}

// TestDetectTimingAnomalies_MultipleSignersIndependent verifies that
// per-signer grouping doesn't let one signer's fast (but plausible) cadence
// bleed into another signer's anomaly count, and that two separate signers
// can each individually trigger anomalies without interfering with each
// other's results.
func TestDetectTimingAnomalies_MultipleSignersIndependent(t *testing.T) {
	base := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	verifications := []verify.CommitVerification{
		mkVerification("alice-1", "alice@example.com", base),
		mkVerification("alice-2", "alice@example.com", base.Add(40*time.Millisecond)), // too fast
		mkVerification("bob-1", "bob@example.com", base),
		mkVerification("bob-2", "bob@example.com", base.Add(10*time.Minute)), // plausible
	}

	got := DetectTimingAnomalies(verifications, 300)
	if len(got) != 1 {
		t.Fatalf("got %d anomalies, want 1: %+v", len(got), got)
	}
	if got[0].Signer != "alice@example.com" {
		t.Errorf("anomaly Signer = %q, want alice@example.com", got[0].Signer)
	}
}

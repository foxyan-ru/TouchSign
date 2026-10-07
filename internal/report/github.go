package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/v66/github"
)

// PostPRComment posts the report's human-readable summary as a comment on
// the pull request that triggered this CI run, using the standard
// environment variables the GitHub Actions runner injects:
//
//   - GITHUB_TOKEN:      a token with `pull-requests: write` permission
//     (typically the workflow's automatic `secrets.GITHUB_TOKEN`, passed
//     through by action.yml).
//   - GITHUB_REPOSITORY: "owner/repo".
//   - GITHUB_EVENT_PATH: path to the JSON payload for the triggering
//     event, from which the PR number is extracted for pull_request and
//     pull_request_target events.
//
// This function has never been executed against the real GitHub API; it is
// written to compile against github.com/google/go-github/v66 and follow
// that client's documented usage, but has not been run or integration
// tested.
func PostPRComment(ctx context.Context, r Report) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("report: GITHUB_TOKEN is not set; cannot post PR comment")
	}

	owner, repo, err := parseRepository(os.Getenv("GITHUB_REPOSITORY"))
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	prNumber, err := resolvePRNumber()
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	client := github.NewClient(nil).WithAuthToken(token)

	body := formatCommentBody(r)

	comment := &github.IssueComment{Body: github.String(body)}

	// Pull request comments (as opposed to review comments anchored to a
	// diff line) are created through the Issues API, since every PR is
	// also an issue in GitHub's data model -- this is the standard,
	// documented way to post a general PR comment via go-github.
	_, _, err = client.Issues.CreateComment(ctx, owner, repo, prNumber, comment)
	if err != nil {
		return fmt.Errorf("report: creating PR comment on %s/%s#%d: %w", owner, repo, prNumber, err)
	}

	return nil
}

func formatCommentBody(r Report) string {
	var b strings.Builder
	b.WriteString("## TouchSign report\n\n")
	if r.Allowed {
		b.WriteString(":white_check_mark: **PASS** -- policy requirements satisfied.\n\n")
	} else {
		b.WriteString(":x: **FAIL** -- one or more policy requirements were not met.\n\n")
	}
	fmt.Fprintf(&b, "- Range: `%s..%s`\n", shortSHA(r.BaseSHA), shortSHA(r.HeadSHA))
	fmt.Fprintf(&b, "- Commits checked: %d\n", len(r.Commits))
	fmt.Fprintf(&b, "- Signature coverage: %.1f%%\n", r.CoveragePercent)
	fmt.Fprintf(&b, "- Timing anomalies: %d\n", len(r.Anomalies))
	fmt.Fprintf(&b, "- Policy violations: %d\n\n", len(r.Policy.Violations))

	if len(r.Anomalies) > 0 {
		b.WriteString("### Anomalies\n\n")
		for _, a := range r.Anomalies {
			fmt.Fprintf(&b, "- `%s`: `%s` and `%s` signed **%dms** apart by `%s`\n",
				a.Type, shortSHA(a.Commits[0]), shortSHA(a.Commits[1]), a.GapMs, a.Signer)
		}
		b.WriteString("\n")
	}

	if len(r.Policy.Violations) > 0 {
		b.WriteString("### Policy violations\n\n")
		for _, v := range r.Policy.Violations {
			fmt.Fprintf(&b, "- %s\n", v)
		}
		b.WriteString("\n")
	}

	b.WriteString("<details><summary>Full JSON report</summary>\n\n```json\n")
	if data, err := r.JSON(); err == nil {
		b.WriteString(data)
	} else {
		b.WriteString(fmt.Sprintf("(failed to marshal report: %v)", err))
	}
	b.WriteString("\n```\n</details>\n")

	return b.String()
}

func parseRepository(spec string) (owner, repo string, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("GITHUB_REPOSITORY is not in \"owner/repo\" form: %q", spec)
	}
	return parts[0], parts[1], nil
}

// githubEventPullRequest is the minimal subset of the pull_request /
// pull_request_target event payload TouchSign needs.
type githubEventPullRequest struct {
	PullRequest struct {
		Number int `json:"number"`
	} `json:"pull_request"`
	Number int `json:"number"` // present on some event shapes directly
}

// resolvePRNumber determines the PR number from the standard GitHub Actions
// environment, preferring the event payload (GITHUB_EVENT_PATH) since it is
// authoritative for pull_request/pull_request_target events, and falling
// back to parsing GITHUB_REF (e.g. "refs/pull/123/merge") for workflows
// that trigger differently but still checkout a PR ref.
func resolvePRNumber() (int, error) {
	if eventPath := os.Getenv("GITHUB_EVENT_PATH"); eventPath != "" {
		data, err := os.ReadFile(eventPath)
		if err == nil {
			var evt githubEventPullRequest
			if jsonErr := json.Unmarshal(data, &evt); jsonErr == nil {
				if evt.PullRequest.Number != 0 {
					return evt.PullRequest.Number, nil
				}
				if evt.Number != 0 {
					return evt.Number, nil
				}
			}
		}
	}

	if ref := os.Getenv("GITHUB_REF"); strings.HasPrefix(ref, "refs/pull/") {
		segments := strings.Split(ref, "/")
		if len(segments) >= 3 {
			if n, err := strconv.Atoi(segments[2]); err == nil {
				return n, nil
			}
		}
	}

	return 0, fmt.Errorf("could not determine pull request number from GITHUB_EVENT_PATH or GITHUB_REF")
}

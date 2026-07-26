package gitea

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	maxCommitStatusContext     = 255
	maxCommitStatusDescription = 255
	maxCommitStatusTargetURL   = 2048
)

// CommitStatus is a native Gitea commit status.
type CommitStatus struct {
	State       string `json:"state"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	Context     string `json:"context"`
}

// CreateCommitStatus creates a status for an immutable commit SHA.
func (c *Client) CreateCommitStatus(ctx context.Context, owner, repo, sha string, status CommitStatus) error {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	sha = strings.TrimSpace(sha)
	status.State = strings.ToLower(strings.TrimSpace(status.State))
	status.Context = strings.TrimSpace(status.Context)
	status.Description = strings.TrimSpace(status.Description)
	status.TargetURL = strings.TrimSpace(status.TargetURL)

	if owner == "" || repo == "" || sha == "" {
		return fmt.Errorf("commit status owner, repo, and sha are required")
	}
	if !validCommitStatusState(status.State) {
		return fmt.Errorf("invalid commit status state %q", status.State)
	}
	if status.Context == "" || len(status.Context) > maxCommitStatusContext {
		return fmt.Errorf("commit status context must be 1..%d bytes", maxCommitStatusContext)
	}
	if len(status.Description) > maxCommitStatusDescription {
		return fmt.Errorf("commit status description exceeds %d bytes", maxCommitStatusDescription)
	}
	if len(status.TargetURL) > maxCommitStatusTargetURL {
		return fmt.Errorf("commit status target URL exceeds %d bytes", maxCommitStatusTargetURL)
	}

	apiPath := "/api/v1/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) +
		"/statuses/" + url.PathEscape(sha)
	if _, err := c.doJSON(ctx, http.MethodPost, apiPath, status); err != nil {
		return fmt.Errorf("create commit status for %s/%s@%s: %w", owner, repo, sha, err)
	}
	return nil
}

func validCommitStatusState(state string) bool {
	switch state {
	case "pending", "success", "error", "failure", "warning":
		return true
	default:
		return false
	}
}

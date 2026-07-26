package gitea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// maxResponseSize limits Gitea API response bodies to 10 MB.
const maxResponseSize = 10 << 20

var safeBareRefName = regexp.MustCompile(`^refs/[A-Za-z0-9._/\-]+$`)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type User struct {
	ID       int64  `json:"id"`
	Login    string `json:"login"`
	FullName string `json:"full_name,omitempty"`
	Email    string `json:"email"`
}

type Repository struct {
	ID       int64  `json:"id"`
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	SSHURL   string `json:"ssh_url"`
	HTMLURL  string `json:"html_url"`
}

type Issue struct {
	ID     int64  `json:"id"`
	Index  int64  `json:"index"`
	Number int64  `json:"number,omitempty"`
	Title  string `json:"title"`
	Body   string `json:"body,omitempty"`
	State  string `json:"state"`
}

type PullRequest struct {
	ID      int64  `json:"id"`
	Index   int64  `json:"index"`
	Number  int64  `json:"number,omitempty"`
	Title   string `json:"title"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
}

type IssueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

// Label is a repository label returned by the Gitea issue-label API.
type Label struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func NewClient(baseURL string, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// CreateOrg creates a new organization and fails if the name is already in
// use. Use this for an unlinked external identity so an existing tenant cannot
// be silently adopted.
func (c *Client) CreateOrg(ctx context.Context, org string) error {
	payload := map[string]any{
		"username":   org,
		"visibility": "public",
	}
	if _, err := c.doJSON(ctx, http.MethodPost, "/api/v1/orgs", payload); err != nil {
		return fmt.Errorf("create unlinked org %q: %w", org, err)
	}
	return nil
}

// EnsureOrg is idempotent and may accept an existing organization. Callers must
// use it only after a durable ownership link has been established.
func (c *Client) EnsureOrg(ctx context.Context, org string) error {
	_, err := c.getOrg(ctx, org)
	if err == nil {
		return nil
	}

	if !isNotFound(err) {
		return err
	}

	payload := map[string]any{
		"username":   org,
		"visibility": "public",
	}
	_, err = c.doJSON(ctx, http.MethodPost, "/api/v1/orgs", payload)
	if err == nil {
		return nil
	}
	if isConflict(err) {
		return nil
	}
	return err
}

// CreateRepo creates a new repository and fails if org/repo already exists.
// Use this when no durable ownership link exists for the repository.
func (c *Client) CreateRepo(ctx context.Context, org string, repo string) (Repository, error) {
	body := map[string]any{
		"name":      repo,
		"private":   false,
		"auto_init": false,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/orgs/"+url.PathEscape(org)+"/repos", body)
	if err != nil {
		return Repository{}, fmt.Errorf("create unlinked repo %q/%q: %w", org, repo, err)
	}
	out, err := parseRepo(resp)
	if err != nil {
		return Repository{}, err
	}
	if out.Owner == "" {
		out.Owner = org
	}
	return out, nil
}

// EnsureRepo is idempotent and may accept an existing repository. Callers must
// use it only after a durable ownership link has been established.
func (c *Client) EnsureRepo(ctx context.Context, org string, repo string) (Repository, error) {
	existing, err := c.GetRepo(ctx, org, repo)
	if err == nil {
		return existing, nil
	}
	if !isNotFound(err) {
		return Repository{}, err
	}

	body := map[string]any{
		"name":      repo,
		"private":   false,
		"auto_init": false,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/orgs/"+url.PathEscape(org)+"/repos", body)
	if err != nil {
		if isConflict(err) {
			return c.GetRepo(ctx, org, repo)
		}
		return Repository{}, err
	}

	out, err := parseRepo(resp)
	if err != nil {
		return Repository{}, err
	}
	if out.Owner == "" {
		out.Owner = org
	}
	return out, nil
}

func (c *Client) ArchiveRepo(ctx context.Context, org string, repo string) error {
	body := map[string]any{"archived": true}
	_, err := c.doJSON(ctx, http.MethodPatch, "/api/v1/repos/"+url.PathEscape(org)+"/"+url.PathEscape(repo), body)
	return err
}

func (c *Client) GetRepo(ctx context.Context, org string, repo string) (Repository, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, "/api/v1/repos/"+url.PathEscape(org)+"/"+url.PathEscape(repo), nil)
	if err != nil {
		return Repository{}, err
	}

	return parseRepo(resp)
}

// GetUser looks up a Gitea user by login name. Returns HTTPError with 404 if not found.
func (c *Client) GetUser(ctx context.Context, login string) (User, error) {
	resp, err := c.doJSON(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(login), nil)
	if err != nil {
		return User{}, err
	}
	return parseUser(resp)
}

// CreateIssue creates a Gitea issue in owner/repo.
func (c *Client) CreateIssue(ctx context.Context, owner string, repo string, title string, body string) (Issue, error) {
	payload := map[string]any{
		"title": title,
		"body":  body,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues", payload)
	if err != nil {
		return Issue{}, err
	}
	return parseIssue(resp)
}

// CreatePullRequest creates a Gitea pull request in owner/repo.
func (c *Client) CreatePullRequest(ctx context.Context, owner string, repo string, head string, base string, title string, body string) (PullRequest, error) {
	payload := map[string]any{
		"head":  head,
		"base":  base,
		"title": title,
		"body":  body,
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/pulls", payload)
	if err != nil {
		return PullRequest{}, err
	}
	return parsePullRequest(resp)
}

// CreateIssueComment creates a comment on a Gitea issue or pull request index.
func (c *Client) CreateIssueComment(ctx context.Context, owner string, repo string, index int64, body string) (IssueComment, error) {
	payload := map[string]any{"body": body}
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues/"+fmt.Sprint(index)+"/comments", payload)
	if err != nil {
		return IssueComment{}, err
	}
	return parseIssueComment(resp)
}

// SetIssueState updates a Gitea issue or pull request state ("open" or "closed").
func (c *Client) SetIssueState(ctx context.Context, owner string, repo string, index int64, state string) (Issue, error) {
	payload := map[string]any{"state": state}
	resp, err := c.doJSON(ctx, http.MethodPatch, "/api/v1/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues/"+fmt.Sprint(index), payload)
	if err != nil {
		return Issue{}, err
	}
	return parseIssue(resp)
}

// AddIssueLabel applies an existing repository or organization label by name.
func (c *Client) AddIssueLabel(ctx context.Context, owner string, repo string, index int64, label string) error {
	payload := map[string]any{"labels": []string{label}}
	_, err := c.doJSON(ctx, http.MethodPost, "/api/v1/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/issues/"+fmt.Sprint(index)+"/labels", payload)
	return err
}

// RemoveIssueLabel removes a matching label from an issue or pull request.
func (c *Client) RemoveIssueLabel(ctx context.Context, owner string, repo string, index int64, label string) error {
	path := "/api/v1/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/issues/" + fmt.Sprint(index) + "/labels"
	resp, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	var labels []Label
	if err := json.Unmarshal(resp, &labels); err != nil {
		return fmt.Errorf("decode Gitea issue labels: %w", err)
	}
	for _, current := range labels {
		if current.Name != label {
			continue
		}
		_, err := c.doJSON(ctx, http.MethodDelete, path+"/"+fmt.Sprint(current.ID), nil)
		return err
	}
	return nil
}

// DeleteBareRef deletes ref from a bare repository using git update-ref -d.
func DeleteBareRef(ctx context.Context, repoPath string, ref string) error {
	if repoPath == "" {
		return fmt.Errorf("repo path is required")
	}
	if !safeBareRefName.MatchString(ref) || strings.Contains(ref, "..") {
		return fmt.Errorf("unsafe ref name %q", ref)
	}
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "update-ref", "-d", ref).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("delete bare ref %s: %w: %s", ref, err, msg)
		}
		return fmt.Errorf("delete bare ref %s: %w", ref, err)
	}
	return nil
}

// CreateUser creates a new Gitea user with the given login, email, and password.
// The user is created with login_name matching login for local auth.
func (c *Client) CreateUser(ctx context.Context, login string, email string, password string) (User, error) {
	body := map[string]any{
		"login":                login,
		"username":             login,
		"email":                email,
		"password":             password,
		"must_change_password": false,
		"visibility":           "public",
	}
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/admin/users", body)
	if err != nil {
		return User{}, err
	}
	return parseUser(resp)
}

func (c *Client) getOrg(ctx context.Context, org string) ([]byte, error) {
	return c.doJSON(ctx, http.MethodGet, "/api/v1/orgs/"+url.PathEscape(org), nil)
}

func (c *Client) doJSON(ctx context.Context, method string, path string, body any) ([]byte, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "token "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}

	return nil, &HTTPError{StatusCode: resp.StatusCode, Body: string(raw)}
}

type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("gitea API status=%d body=%s", e.StatusCode, e.Body)
}

func parseIssue(resp []byte) (Issue, error) {
	var issue Issue
	if err := json.Unmarshal(resp, &issue); err != nil {
		return Issue{}, fmt.Errorf("decode gitea issue: %w", err)
	}
	if issue.Index == 0 && issue.Number != 0 {
		issue.Index = issue.Number
	}
	if issue.Number == 0 && issue.Index != 0 {
		issue.Number = issue.Index
	}
	return issue, nil
}

func parsePullRequest(resp []byte) (PullRequest, error) {
	var pr PullRequest
	if err := json.Unmarshal(resp, &pr); err != nil {
		return PullRequest{}, fmt.Errorf("decode gitea pull request: %w", err)
	}
	if pr.Index == 0 && pr.Number != 0 {
		pr.Index = pr.Number
	}
	if pr.Number == 0 && pr.Index != 0 {
		pr.Number = pr.Index
	}
	return pr, nil
}

func parseIssueComment(resp []byte) (IssueComment, error) {
	var comment IssueComment
	if err := json.Unmarshal(resp, &comment); err != nil {
		return IssueComment{}, fmt.Errorf("decode gitea issue comment: %w", err)
	}
	return comment, nil
}

func parseRepo(resp []byte) (Repository, error) {
	var raw struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		CloneURL string `json:"clone_url"`
		SSHURL   string `json:"ssh_url"`
		HTMLURL  string `json:"html_url"`
		Owner    struct {
			UserName string `json:"username"`
		} `json:"owner"`
	}
	if err := json.Unmarshal(resp, &raw); err != nil {
		return Repository{}, fmt.Errorf("decode gitea repo: %w", err)
	}
	return Repository{
		ID:       raw.ID,
		Owner:    raw.Owner.UserName,
		Name:     raw.Name,
		CloneURL: raw.CloneURL,
		SSHURL:   raw.SSHURL,
		HTMLURL:  raw.HTMLURL,
	}, nil
}

func isNotFound(err error) bool {
	e, ok := err.(*HTTPError)
	return ok && e.StatusCode == http.StatusNotFound
}

func isConflict(err error) bool {
	e, ok := err.(*HTTPError)
	return ok && e.StatusCode == http.StatusConflict
}

func parseUser(resp []byte) (User, error) {
	var u User
	if err := json.Unmarshal(resp, &u); err != nil {
		return User{}, fmt.Errorf("decode gitea user: %w", err)
	}
	return u, nil
}

// IsNotFound reports whether the error is a 404 from the Gitea API.
func IsNotFound(err error) bool {
	return isNotFound(err)
}

package gitea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type Repository struct {
	ID       int64  `json:"id"`
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	SSHURL   string `json:"ssh_url"`
	HTMLURL  string `json:"html_url"`
}

func NewClient(baseURL string, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{},
	}
}

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

	raw, err := io.ReadAll(resp.Body)
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

func parseRepo(resp []byte) (Repository, error) {
	var raw struct {
		ID       int64 `json:"id"`
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

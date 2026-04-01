package gitea

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sharegap/grasp-gitea/internal/nostrprofile"
)

// UpdateOrgProfile syncs a Nostr kind:0 Profile into a Gitea org.
// Sets full_name, description, and website. Non-fatal on partial failure.
func (c *Client) UpdateOrgProfile(ctx context.Context, org string, p nostrprofile.Profile) error {
	if p.IsEmpty() {
		return nil
	}

	body := map[string]any{}
	if p.DisplayName != "" {
		body["full_name"] = p.DisplayName
	}
	if p.About != "" {
		body["description"] = p.About
	}
	if p.Website != "" {
		body["website"] = p.Website
	}

	if len(body) == 0 {
		return nil
	}

	_, err := c.doJSON(ctx, http.MethodPatch, "/api/v1/orgs/"+url.PathEscape(org), body)
	return err
}

// UpdateUserFullName updates the full_name field for a Gitea user via the admin API.
// This is the only profile field updatable for users without acting as the user.
func (c *Client) UpdateUserFullName(ctx context.Context, username string, fullName string) error {
	if fullName == "" {
		return nil
	}
	// Admin user edit requires login_name and source_id to be present.
	u, found, err := c.GetUserByUsername(ctx, username)
	if err != nil || !found {
		return err
	}
	body := map[string]any{
		"login_name": u.Username,
		"source_id":  0,
		"full_name":  fullName,
	}
	_, err = c.doJSON(ctx, http.MethodPatch, "/api/v1/admin/users/"+url.PathEscape(username), body)
	return err
}

// SetOrgAvatarFromURL downloads the image at imageURL and sets it as the
// Gitea org's avatar. Non-fatal on download failure or unsupported image type.
func (c *Client) SetOrgAvatarFromURL(ctx context.Context, org string, imageURL string) error {
	if imageURL == "" {
		return nil
	}

	imgData, contentType, err := downloadImage(ctx, imageURL)
	if err != nil {
		return fmt.Errorf("download avatar from %s: %w", imageURL, err)
	}

	// Gitea accepts PNG, JPEG, GIF. Validate content type.
	switch contentType {
	case "image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp":
		// OK
	default:
		return fmt.Errorf("unsupported avatar image type %q from %s", contentType, imageURL)
	}

	encoded := base64.StdEncoding.EncodeToString(imgData)

	body := map[string]any{"image": encoded}
	_, err = c.doJSON(ctx, http.MethodPost, "/api/v1/orgs/"+url.PathEscape(org)+"/avatar", body)
	return err
}

// SyncNostrProfile syncs a kind:0 Profile into both a Gitea org and user account.
// All operations are non-fatal — a failure in one step does not prevent others.
// Returns a combined error summary if any steps fail.
func (c *Client) SyncNostrProfile(ctx context.Context, username string, org string, p nostrprofile.Profile) error {
	if p.IsEmpty() {
		return nil
	}

	var errs []string

	// Sync org profile (full_name, description, website).
	if org != "" {
		if err := c.UpdateOrgProfile(ctx, org, p); err != nil {
			errs = append(errs, fmt.Sprintf("org profile: %v", err))
		}
		// Sync org avatar.
		if p.Picture != "" {
			if err := c.SetOrgAvatarFromURL(ctx, org, p.Picture); err != nil {
				errs = append(errs, fmt.Sprintf("org avatar: %v", err))
			}
		}
	}

	// Sync user full_name (the only field we can set via admin API).
	if username != "" && p.DisplayName != "" {
		if err := c.UpdateUserFullName(ctx, username, p.DisplayName); err != nil {
			errs = append(errs, fmt.Sprintf("user full_name: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("profile sync partial failure: %v", errs)
	}
	return nil
}

// downloadImage fetches an image URL and returns the raw bytes and content-type.
// Enforces a 5s timeout and a 2MB size limit.
func downloadImage(ctx context.Context, imageURL string) ([]byte, string, error) {
	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, imageURL, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d fetching avatar", resp.StatusCode)
	}

	const maxSize = 2 << 20 // 2MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, "", err
	}

	ct := resp.Header.Get("Content-Type")
	// Strip charset suffix if present (e.g. "image/jpeg; charset=utf-8")
	if i := len(ct); i > 0 {
		for j := 0; j < len(ct); j++ {
			if ct[j] == ';' {
				ct = ct[:j]
				break
			}
		}
	}

	return data, ct, nil
}

package gitea

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sharegap/grasp-gitea/internal/nostrprofile"
	"github.com/sharegap/grasp-gitea/internal/safefetch"
)

// Gitea profile field bounds. Values are truncated by Unicode code point.
const (
	maxFullNameRunes    = 100
	maxDescriptionRunes = 255
	maxWebsiteBytes     = 255
)

// ErrImageInvalid is a permanent failure for a specific picture (bad URL,
// unsupported type, oversized): sync the text, keep the existing avatar, and
// advance the cursor. ErrImageTransient is a retryable download failure:
// change nothing and retry later.
var (
	ErrImageInvalid   = errors.New("profile image is invalid")
	ErrImageTransient = errors.New("profile image download failed transiently")
)

// UserProfileFields is the normalized, bounded set of Gitea user fields
// derived from a kind:0 profile. Empty fields are written as empty so a newer
// profile that cleared a value clears it in Gitea too.
type UserProfileFields struct {
	FullName    string
	Description string
	Website     string
}

// NormalizeUserProfile maps a kind:0 profile to bounded, control-stripped
// Gitea user fields. A website that is not an absolute http(s) URL with a
// host and no userinfo is dropped to empty rather than written.
func NormalizeUserProfile(p nostrprofile.Profile) UserProfileFields {
	f := UserProfileFields{
		FullName:    truncateRunes(stripControls(p.DisplayName, false), maxFullNameRunes),
		Description: truncateRunes(stripControls(p.About, true), maxDescriptionRunes),
	}
	if w := sanitizeWebsite(p.Website); w != "" {
		f.Website = w
	}
	return f
}

// stripControls removes C0 control characters. When keepBreaks is true,
// newlines and tabs are preserved (for multi-line descriptions).
func stripControls(s string, keepBreaks bool) string {
	s = strings.TrimSpace(s)
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			if keepBreaks {
				return r
			}
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return strings.TrimSpace(string(runes[:max]))
}

// sanitizeWebsite accepts only an absolute http(s) URL with a host and no
// userinfo, within the length bound. Anything else (including javascript:)
// returns empty.
func sanitizeWebsite(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxWebsiteBytes {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	return raw
}

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
	u, err := c.GetUser(ctx, username)
	if err != nil {
		return err
	}
	body := map[string]any{
		"login_name": u.Login,
		"source_id":  0,
		"full_name":  fullName,
	}
	_, err = c.doJSON(ctx, http.MethodPatch, "/api/v1/admin/users/"+url.PathEscape(username), body)
	return err
}

// UpdateUserProfileFields sets full_name, description, and website on a Gitea
// user via the admin edit API. Empty fields are written as empty so a newer
// profile that cleared a value clears it in Gitea. Admin edit requires
// login_name and source_id in the body. It cannot set the avatar.
func (c *Client) UpdateUserProfileFields(ctx context.Context, username string, f UserProfileFields) error {
	u, err := c.GetUser(ctx, username)
	if err != nil {
		return err
	}
	body := map[string]any{
		"login_name":  u.Login,
		"source_id":   0,
		"full_name":   f.FullName,
		"description": f.Description,
		"website":     f.Website,
	}
	_, err = c.doJSONBasic(ctx, http.MethodPatch, "/api/v1/admin/users/"+url.PathEscape(username), body)
	return err
}

// SetUserAvatarBasic sets a user's custom avatar by authenticating AS that
// user (Basic login:PAT) against POST /api/v1/user/avatar. Admin edit cannot
// set a user avatar, so the caller supplies a short-lived write:user PAT.
func (c *Client) SetUserAvatarBasic(ctx context.Context, username, pat string, image []byte) error {
	body := map[string]any{"image": base64.StdEncoding.EncodeToString(image)}
	_, err := c.doAsUser(ctx, http.MethodPost, "/api/v1/user/avatar", username, pat, body)
	return err
}

// DeleteUserAvatarBasic clears a user's custom avatar as that user.
func (c *Client) DeleteUserAvatarBasic(ctx context.Context, username, pat string) error {
	_, err := c.doAsUser(ctx, http.MethodDelete, "/api/v1/user/avatar", username, pat, nil)
	return err
}

// GetAuthenticatedUserBasic returns the user the supplied PAT authenticates
// as. Gitea's Basic auth binds the password (PAT) to its owner and ignores
// the Basic username, so the caller MUST verify this id before mutating.
func (c *Client) GetAuthenticatedUserBasic(ctx context.Context, username, pat string) (User, error) {
	resp, err := c.doAsUser(ctx, http.MethodGet, "/api/v1/user", username, pat, nil)
	if err != nil {
		return User{}, err
	}
	return parseUser(resp)
}

// PrepareUserAvatarImage downloads and validates a picture for use as a Gitea
// avatar, classifying failures as permanent (ErrImageInvalid) or transient
// (ErrImageTransient) so the caller can decide whether to advance the cursor.
func PrepareUserAvatarImage(ctx context.Context, pictureURL string) ([]byte, error) {
	data, contentType, err := downloadImage(ctx, pictureURL)
	if err != nil {
		// safefetch rejects bad/unsafe URLs before any request; treat those
		// as permanent, and network/HTTP failures as transient.
		if errors.Is(err, errImagePermanent) {
			return nil, fmt.Errorf("%w: %v", ErrImageInvalid, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrImageTransient, err)
	}
	switch contentType {
	case "image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp":
		return data, nil
	default:
		return nil, fmt.Errorf("%w: unsupported image type %q", ErrImageInvalid, contentType)
	}
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

// errImagePermanent classifies a download failure as caused by the URL
// itself (unsafe/non-HTTPS/oversized/unreadable) rather than transient
// network trouble, so PrepareUserAvatarImage can map it to ErrImageInvalid.
var errImagePermanent = errors.New("permanent image error")

var avatarHTTPClient = safefetch.NewClient()

// downloadImage fetches an image URL and returns the raw bytes and content-type.
// Enforces a 5s timeout and a strict 2MB size limit. The safefetch client
// requires HTTPS and rejects private/reserved destinations on every redirect.
func downloadImage(ctx context.Context, imageURL string) ([]byte, string, error) {
	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, imageURL, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := avatarHTTPClient.Do(req)
	if err != nil {
		// safefetch policy rejections (non-HTTPS, private/reserved host,
		// credentials in URL) surface here before any bytes move and are
		// permanent for this URL; a typed sentinel avoids matching text.
		if errors.Is(err, safefetch.ErrPolicy) {
			return nil, "", fmt.Errorf("%w: %v", errImagePermanent, err)
		}
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d fetching avatar", resp.StatusCode)
	}

	const maxSize = 2 << 20 // 2MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxSize {
		return nil, "", fmt.Errorf("%w: avatar exceeds %d-byte size limit", errImagePermanent, maxSize)
	}

	// Do not trust the remote Content-Type header; sniff the bounded payload.
	return data, http.DetectContentType(data), nil
}

// doAsUser performs a request authenticated as an arbitrary Gitea user via
// Basic login:PAT (not the admin identity). Used for the per-user avatar
// endpoints, which admin edit cannot reach.
func (c *Client) doAsUser(ctx context.Context, method, path, username, pat string, body any) ([]byte, error) {
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
	req.SetBasicAuth(username, pat)

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

package gitea

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
)

// User represents a Gitea user.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"login"`
	Email    string `json:"email"`
}

// GetUserByUsername returns the user, or (User{}, false, nil) if not found.
func (c *Client) GetUserByUsername(ctx context.Context, username string) (User, bool, error) {
	resp, err := c.doJSON(ctx, "GET", "/api/v1/users/"+url.PathEscape(username), nil)
	if err != nil {
		if isNotFound(err) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	u, err := parseUser(resp)
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// CreateUser creates a new Gitea user via the admin API.
// A random password is set — the user is expected to authenticate via NIP-07 only.
func (c *Client) CreateUser(ctx context.Context, username, email string) (User, error) {
	pw, err := randomPassword()
	if err != nil {
		return User{}, fmt.Errorf("generate password: %w", err)
	}

	body := map[string]any{
		"username":             username,
		"email":                email,
		"password":             pw,
		"must_change_password": false,
		"source_id":            0,
		"login_name":           username,
	}

	resp, err := c.doJSON(ctx, "POST", "/api/v1/admin/users", body)
	if err != nil {
		if isConflict(err) {
			// Race: user was created between our check and create. Fetch it.
			u, found, fetchErr := c.GetUserByUsername(ctx, username)
			if fetchErr != nil {
				return User{}, fetchErr
			}
			if found {
				return u, nil
			}
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}

	return parseUser(resp)
}

// EnsureUser returns the existing user or creates one if missing.
func (c *Client) EnsureUser(ctx context.Context, username, email string) (User, error) {
	u, found, err := c.GetUserByUsername(ctx, username)
	if err != nil {
		return User{}, err
	}
	if found {
		return u, nil
	}
	return c.CreateUser(ctx, username, email)
}

func parseUser(resp []byte) (User, error) {
	var raw struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(resp, &raw); err != nil {
		return User{}, fmt.Errorf("parse user: %w", err)
	}
	return User{
		ID:       raw.ID,
		Username: raw.Login,
		Email:    raw.Email,
	}, nil
}

func randomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

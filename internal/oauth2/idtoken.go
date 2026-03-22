package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// mintIDToken produces a minimal HS256-signed JWT id_token for inclusion in
// the token endpoint response. Gitea's OIDC client requires an id_token to
// extract the subject identity; without it, login fails with
// "cannot get user information without id_token".
//
// Claims included: iss, sub, aud, iat, exp, preferred_username, email.
func mintIDToken(cfg Config, pubkey, username, email string, ttl time.Duration) (string, error) {
	iss := strings.TrimRight(cfg.BridgePublicURL, "/")
	now := time.Now().Unix()

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	payload := map[string]any{
		"iss":                iss,
		"sub":                pubkey,
		"aud":                cfg.ClientID,
		"iat":                now,
		"exp":                now + int64(ttl.Seconds()),
		"preferred_username": username,
		"name":               username,
		"email":              email,
	}

	hdrJSON, _ := json.Marshal(header)
	payJSON, _ := json.Marshal(payload)

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	sigInput := hdrB64 + "." + payB64

	mac := hmac.New(sha256.New, []byte(cfg.ClientSecret))
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return sigInput + "." + sig, nil
}

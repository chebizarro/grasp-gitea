package oauth2

import (
	"net/http"
	"strings"
)

// HandleDiscovery serves the OIDC discovery document at /.well-known/openid-configuration.
// Gitea uses this to auto-discover the auth/token/userinfo endpoints.
func (p *Provider) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(p.cfg.BridgePublicURL, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/auth/oauth2/authorize",
		"token_endpoint":                        base + "/auth/oauth2/token",
		"userinfo_endpoint":                     base + "/auth/oauth2/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"sub", "preferred_username", "name", "email"},
	})
}

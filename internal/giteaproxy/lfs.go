// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/auth"
)

// maxLFSBatchBody bounds the LFS batch JSON the proxy will buffer to learn
// the requested operation. git-lfs batches are small (100 objects by
// default); object content never flows through this path.
const maxLFSBatchBody = 1 << 20

// maxLFSBatchResponseBody bounds the batch response the proxy will buffer
// to rewrite backend-origin transfer URLs and sanitize action credentials.
const maxLFSBatchResponseBody = 8 << 20

// IsLFSSubpath recognizes LFS endpoints below a mapped repository's .git/
// path (batch, object transfer, locks).
func IsLFSSubpath(subpath string) bool {
	return subpath == "info/lfs" || strings.HasPrefix(subpath, "info/lfs/")
}

// resolveLFSBatchScope reads the bounded batch request body, maps the LFS
// operation to the bridge scope it requires, and rewinds the body for
// forwarding. Anything unbounded, unreadable, or unknown fails closed.
func resolveLFSBatchScope(r *http.Request) (string, bool) {
	if len(r.TransferEncoding) > 0 || r.ContentLength <= 0 || r.ContentLength > maxLFSBatchBody {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxLFSBatchBody+1))
	if err != nil || int64(len(data)) != r.ContentLength {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(data))

	var req struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(data, &req) != nil {
		return "", false
	}
	switch req.Operation {
	case "download":
		return auth.ScopeLFSRead, true
	case "upload":
		return auth.ScopeLFSWrite, true
	default:
		return "", false
	}
}

// rewriteLFSBatchBody rewrites backend-origin transfer URLs in a batch
// response to the canonical public origin and sanitizes action credentials.
// When requireSanitization is true, an unsafe response must not be forwarded:
// the caller replaces it with a 502 rather than risking disclosure of the
// bridge-injected credential.
func (p *Proxy) rewriteLFSBatchBody(resp *http.Response, publicAuthorization, hiddenAuthorization string, requireSanitization bool) bool {
	if p.publicURL == "" || resp.Body == nil {
		return !requireSanitization
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return !requireSanitization
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(strings.ToLower(ct), "json") {
		return !requireSanitization
	}
	if resp.ContentLength > maxLFSBatchResponseBody {
		return !requireSanitization
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLFSBatchResponseBody+1))
	closeErr := resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil || closeErr != nil || len(data) > maxLFSBatchResponseBody {
		return !requireSanitization
	}

	// UseNumber preserves large integers (object size) and unknown numeric
	// fields exactly; a plain unmarshal would round them through float64.
	var envelope map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if dec.Decode(&envelope) != nil {
		return !requireSanitization
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return !requireSanitization
	}

	changed, safe := p.rewriteLFSActions(envelope, publicAuthorization, hiddenAuthorization)
	if !safe {
		return !requireSanitization
	}
	if !changed {
		return true
	}
	rewritten, err := json.Marshal(envelope)
	if err != nil {
		return !requireSanitization
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	// Entity validators no longer describe these bytes.
	resp.Header.Del("ETag")
	resp.Header.Del("Digest")
	resp.Header.Del("Content-MD5")
	return true
}

// rewriteLFSActions walks objects[*].actions[*]. Backend-origin hrefs are
// rewritten to the public origin. Authorization is changed only for actions
// targeting that public origin or the exact backend origin: authenticated
// transfers receive the caller's bridge token and anonymous transfers have
// authorization removed. External action headers are left intact except when
// they exactly match the credential injected by the bridge.
func (p *Proxy) rewriteLFSActions(envelope map[string]any, publicAuthorization, hiddenAuthorization string) (changed, safe bool) {
	objectsValue, exists := envelope["objects"]
	if !exists {
		return false, false
	}
	objects, ok := objectsValue.([]any)
	if !ok {
		return false, false
	}

	for _, o := range objects {
		object, ok := o.(map[string]any)
		if !ok {
			return changed, false
		}
		actionsValue, exists := object["actions"]
		if !exists || actionsValue == nil {
			continue
		}
		actions, ok := actionsValue.(map[string]any)
		if !ok {
			return changed, false
		}
		for _, a := range actions {
			action, ok := a.(map[string]any)
			if !ok {
				return changed, false
			}
			href, ok := action["href"].(string)
			if !ok || href == "" {
				return changed, false
			}
			parsed, err := url.Parse(href)
			if err != nil || !parsed.IsAbs() {
				return changed, false
			}

			backendOrigin := strings.EqualFold(parsed.Scheme, p.target.Scheme) &&
				strings.EqualFold(parsed.Host, p.target.Host)
			publicOrigin := strings.EqualFold(parsed.Scheme, p.publicScheme) &&
				strings.EqualFold(parsed.Host, p.publicHost)

			headersValue, hasHeaders := action["header"]
			var headers map[string]any
			if hasHeaders {
				headers, ok = headersValue.(map[string]any)
				if !ok {
					return changed, false
				}
			}
			if !backendOrigin && !publicOrigin {
				// Preserve credentials meant for the external host, but never
				// forward the exact Basic credential injected by the bridge.
				for key, value := range headers {
					if strings.EqualFold(key, "Authorization") && value == hiddenAuthorization && hiddenAuthorization != "" {
						delete(headers, key)
						changed = true
					}
				}
				continue
			}
			if backendOrigin {
				action["href"] = p.publicURL + strings.TrimPrefix(href, parsed.Scheme+"://"+parsed.Host)
				changed = true
			}

			for key := range headers {
				if strings.EqualFold(key, "Authorization") {
					delete(headers, key)
					changed = true
				}
			}
			if publicAuthorization != "" {
				if headers == nil {
					headers = make(map[string]any)
					action["header"] = headers
				}
				headers["Authorization"] = publicAuthorization
				changed = true
			}
		}
	}
	return changed, true
}

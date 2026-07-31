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
// to rewrite backend-origin transfer URLs. Larger responses pass through
// unmodified rather than being truncated.
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
// response to the canonical public origin. With ROOT_URL set to the public
// origin Gitea already emits public hrefs; this is defense in depth so the
// private upstream address can never leak to an LFS client. The body is
// parsed and only `objects[*].actions[*].href` values whose scheme and host
// exactly equal the configured upstream are touched — a substring
// substitution would also rewrite hostile look-alikes and could mutate
// unrelated fields. Compressed, oversized, or unparsable responses pass
// through unmodified.
func (p *Proxy) rewriteLFSBatchBody(resp *http.Response) {
	if p.publicURL == "" || resp.Body == nil {
		return
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return
	}
	if resp.ContentLength > maxLFSBatchResponseBody {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLFSBatchResponseBody+1))
	closeErr := resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil || closeErr != nil || len(data) > maxLFSBatchResponseBody {
		return
	}

	// UseNumber preserves large integers (object size) and unknown numeric
	// fields exactly; a plain unmarshal would round them through float64.
	var envelope map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if dec.Decode(&envelope) != nil {
		return
	}
	if !p.rewriteLFSActionHrefs(envelope) {
		return // nothing changed; keep the original bytes
	}
	rewritten, err := json.Marshal(envelope)
	if err != nil {
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	// Entity validators no longer describe these bytes.
	resp.Header.Del("ETag")
	resp.Header.Del("Digest")
	resp.Header.Del("Content-MD5")
}

// rewriteLFSActionHrefs walks objects[*].actions[*].href, rewriting exact
// backend-origin URLs to the public origin. Reports whether anything changed.
func (p *Proxy) rewriteLFSActionHrefs(envelope map[string]any) bool {
	objects, _ := envelope["objects"].([]any)
	changed := false
	for _, o := range objects {
		object, _ := o.(map[string]any)
		actions, _ := object["actions"].(map[string]any)
		for _, a := range actions {
			action, _ := a.(map[string]any)
			href, _ := action["href"].(string)
			if href == "" {
				continue
			}
			parsed, err := url.Parse(href)
			if err != nil || !parsed.IsAbs() {
				continue
			}
			if !strings.EqualFold(parsed.Scheme, p.target.Scheme) ||
				!strings.EqualFold(parsed.Host, p.target.Host) {
				continue
			}
			action["href"] = p.publicURL + strings.TrimPrefix(href, parsed.Scheme+"://"+parsed.Host)
			changed = true
		}
	}
	return changed
}

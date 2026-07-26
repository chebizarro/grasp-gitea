package loom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/sharegap/grasp-gitea/internal/safefetch"
)

const (
	defaultBlossomMaxBytes = int64(1 << 20)
	defaultLogTailBytes    = 160
)

// LogArtifact is returned only after size and digest verification succeed.
type LogArtifact struct {
	URL    string
	Digest string
	Size   int64
	Tail   string
}

type LogFetcher interface {
	Fetch(context.Context, string) (LogArtifact, error)
}

type BlossomFetcher struct {
	client   *http.Client
	maxBytes int64
	tailSize int
}

func NewBlossomFetcher(maxBytes int64) *BlossomFetcher {
	if maxBytes <= 0 {
		maxBytes = defaultBlossomMaxBytes
	}
	return &BlossomFetcher{client: safefetch.NewClient(), maxBytes: maxBytes, tailSize: defaultLogTailBytes}
}

func newBlossomFetcher(client *http.Client, maxBytes int64) *BlossomFetcher {
	if maxBytes <= 0 {
		maxBytes = defaultBlossomMaxBytes
	}
	return &BlossomFetcher{client: client, maxBytes: maxBytes, tailSize: defaultLogTailBytes}
}

// Fetch accepts only canonical Blossom URLs whose final path segment is the
// expected 32-byte SHA-256 digest.
func (f *BlossomFetcher) Fetch(ctx context.Context, rawURL string) (LogArtifact, error) {
	if f == nil || f.client == nil {
		return LogArtifact{}, fmt.Errorf("Blossom fetcher is not configured")
	}
	digest, err := blossomDigest(rawURL)
	if err != nil {
		return LogArtifact{}, err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return LogArtifact{}, err
	}
	req.Header.Set("Accept", "text/plain, application/octet-stream")
	resp, err := f.client.Do(req)
	if err != nil {
		return LogArtifact{}, fmt.Errorf("guarded Blossom fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return LogArtifact{}, fmt.Errorf("Blossom response status %d", resp.StatusCode)
	}
	if resp.ContentLength > f.maxBytes {
		return LogArtifact{}, fmt.Errorf("Blossom log exceeds %d-byte cap", f.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return LogArtifact{}, fmt.Errorf("read Blossom log: %w", err)
	}
	if int64(len(body)) > f.maxBytes {
		return LogArtifact{}, fmt.Errorf("Blossom log exceeds %d-byte cap", f.maxBytes)
	}
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if actual != digest {
		return LogArtifact{}, fmt.Errorf("Blossom SHA-256 mismatch")
	}
	return LogArtifact{URL: rawURL, Digest: digest, Size: int64(len(body)), Tail: logTail(body, f.tailSize)}, nil
}

func blossomDigest(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" ||
		u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("invalid Blossom HTTPS URL")
	}
	digest := path.Base(u.EscapedPath())
	decoded, err := url.PathUnescape(digest)
	if err != nil || len(decoded) != 64 {
		return "", fmt.Errorf("Blossom URL must reference a SHA-256 digest")
	}
	raw, err := hex.DecodeString(decoded)
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("Blossom URL must reference a SHA-256 digest")
	}
	return strings.ToLower(decoded), nil
}

func logTail(body []byte, limit int) string {
	if limit <= 0 || len(body) == 0 {
		return ""
	}
	if len(body) > limit {
		body = body[len(body)-limit:]
		for len(body) > 0 && body[0]&0xc0 == 0x80 {
			body = body[1:]
		}
	}
	var b strings.Builder
	space := false
	for _, r := range strings.ToValidUTF8(string(body), "�") {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

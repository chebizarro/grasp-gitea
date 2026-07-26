package loom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestBlossomFetcherVerifiesDigestCapAndTail(t *testing.T) {
	body := append([]byte("first line\nlast log line"), 0)
	sum := sha256.Sum256(body)
	rawURL := "https://blossom.example/" + hex.EncodeToString(sum[:])
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))),
			ContentLength: int64(len(body)), Header: make(http.Header), Request: req}, nil
	})}
	fetcher := newBlossomFetcher(client, int64(len(body)))
	artifact, err := fetcher.Fetch(context.Background(), rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Digest != hex.EncodeToString(sum[:]) || artifact.Size != int64(len(body)) ||
		artifact.Tail != "first line last log line" {
		t.Fatalf("artifact = %#v", artifact)
	}

	if _, err := newBlossomFetcher(client, int64(len(body)-1)).Fetch(context.Background(), rawURL); err == nil {
		t.Fatal("oversized Blossom body accepted")
	}
	badURL := "https://blossom.example/" + strings.Repeat("0", 64)
	if _, err := fetcher.Fetch(context.Background(), badURL); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func TestBlossomFetcherUsesSSRFEgressGuard(t *testing.T) {
	sum := sha256.Sum256([]byte("log"))
	rawURL := "https://127.0.0.1/" + hex.EncodeToString(sum[:])
	if _, err := NewBlossomFetcher(1024).Fetch(context.Background(), rawURL); err == nil ||
		!strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("private Blossom target was not rejected by safefetch: %v", err)
	}
}

func TestBlossomDigestRequiresCanonicalReference(t *testing.T) {
	for _, raw := range []string{
		"http://blossom.example/" + strings.Repeat("0", 64),
		"https://blossom.example/not-a-digest",
		"https://user@blossom.example/" + strings.Repeat("0", 64),
	} {
		if _, err := blossomDigest(raw); err == nil {
			t.Fatalf("unsafe/noncanonical URL accepted: %s", raw)
		}
	}
}

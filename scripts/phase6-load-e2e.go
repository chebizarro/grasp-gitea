//go:build ignore

// Command phase6-load-e2e drives concurrent traffic through the Phase 6 nginx
// endpoint and fails on any transport error, unexpected status, or missing
// bridge replica.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type surface struct {
	name   string
	path   string
	status int
}

type result struct {
	requests int
	errors   int
	byName   map[string]int
	upstream map[string]int
	firstErr string
}

func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:58096", "nginx base URL")
	duration := flag.Duration("duration", 5*time.Second, "load duration")
	concurrency := flag.Int("concurrency", 16, "concurrent workers")
	mode := flag.String("mode", "all", "traffic set: all, forwarded, or auth")
	minUpstreams := flag.Int("min-upstreams", 2, "minimum distinct bridge upstreams required")
	flag.Parse()
	if *concurrency < 1 || *duration <= 0 {
		fail("concurrency and duration must be positive")
	}

	forwarded := []surface{
		{name: "git", path: "/owner/repo.git/info/refs?service=git-upload-pack", status: http.StatusOK},
		{name: "package", path: "/api/packages/owner/generic/pkg/1.0/file.bin", status: http.StatusOK},
		{name: "api", path: "/api/v1/version", status: http.StatusOK},
	}
	auth := surface{name: "auth", path: "/auth/nip46/status?session=phase6-chaos-missing", status: http.StatusNotFound}
	var surfaces []surface
	switch *mode {
	case "all":
		surfaces = append(forwarded, auth)
	case "forwarded":
		surfaces = forwarded
	case "auth":
		surfaces = []surface{auth}
	default:
		fail("unknown mode %q", *mode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = *concurrency * 2
	transport.MaxIdleConnsPerHost = *concurrency
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	defer transport.CloseIdleConnections()
	got := result{byName: make(map[string]int), upstream: make(map[string]int)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for worker := 0; worker < *concurrency; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for requestNumber := 0; ; requestNumber++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				s := surfaces[(worker+requestNumber)%len(surfaces)]
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(*baseURL, "/")+s.path, nil)
				if err != nil {
					recordError(&mu, &got, fmt.Sprintf("%s request: %v", s.name, err))
					continue
				}
				// A stable credential-shaped header makes cross-node forwarding
				// differences observable without depending on a real Gitea install.
				req.Header.Set("Authorization", "Basic cGhhc2U2OnN0YWJsZQ==")
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						recordError(&mu, &got, fmt.Sprintf("%s transport: %v", s.name, err))
					}
					continue
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				// The duration boundary cancels requests still in flight. Those are
				// outside the completed-request error-rate denominator.
				if readErr != nil && ctx.Err() != nil {
					continue
				}
				mu.Lock()
				got.requests++
				got.byName[s.name]++
				for _, upstream := range strings.FieldsFunc(resp.Header.Get("X-Grasp-Upstream"), func(r rune) bool { return r == ',' || r == ' ' }) {
					if upstream != "" {
						got.upstream[upstream]++
					}
				}
				if readErr != nil || resp.StatusCode != s.status {
					got.errors++
					if got.firstErr == "" {
						got.firstErr = fmt.Sprintf("%s status=%d want=%d read=%v", s.name, resp.StatusCode, s.status, readErr)
					}
				}
				mu.Unlock()
			}
		}(worker)
	}
	wg.Wait()

	names := make([]string, 0, len(got.upstream))
	for name := range got.upstream {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("load summary: requests=%d errors=%d surfaces=%v upstreams=%v\n", got.requests, got.errors, got.byName, names)
	if got.requests == 0 {
		fail("no completed requests")
	}
	if got.errors != 0 {
		fail("non-flat error rate: %d/%d requests failed; first=%s", got.errors, got.requests, got.firstErr)
	}
	if len(names) < *minUpstreams {
		fail("observed %d bridge upstreams, want at least %d: %v", len(names), *minUpstreams, names)
	}
}

func recordError(mu *sync.Mutex, got *result, message string) {
	mu.Lock()
	defer mu.Unlock()
	got.errors++
	if got.firstErr == "" {
		got.firstErr = message
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

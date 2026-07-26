package safefetch

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestValidateHTTPSURLPolicy(t *testing.T) {
	resolver := fakeResolver{
		"public.example":   {netip.MustParseAddr("93.184.216.34")},
		"metadata.example": {netip.MustParseAddr("169.254.169.254")},
		"mixed.example":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.1")},
	}
	tests := []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "public HTTPS", raw: "https://public.example/avatar.png", ok: true},
		{name: "HTTP", raw: "http://public.example/avatar.png"},
		{name: "loopback literal", raw: "https://127.0.0.1/avatar.png"},
		{name: "IPv6 loopback", raw: "https://[::1]/avatar.png"},
		{name: "link local metadata", raw: "https://metadata.example/latest/meta-data"},
		{name: "mixed public and private DNS", raw: "https://mixed.example/avatar.png"},
		{name: "cloud metadata CGNAT", raw: "https://100.100.100.200/latest/meta-data"},
		{name: "credentials", raw: "https://user:pass@public.example/repo.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHTTPSURL(context.Background(), tt.raw, resolver)
			if tt.ok && err != nil {
				t.Fatalf("expected URL to pass: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected URL to be rejected")
			}
		})
	}
}

func TestValidateGitCloneURL(t *testing.T) {
	resolver := fakeResolver{"git.example": {netip.MustParseAddr("93.184.216.34")}}
	if err := validateGitCloneURL(context.Background(), "https://git.example/alice/repo.git", resolver); err != nil {
		t.Fatalf("valid clone URL rejected: %v", err)
	}
	for _, raw := range []string{
		"ssh://git@git.example/alice/repo.git",
		"git://git.example/alice/repo.git",
		"file:///tmp/repo",
		"https://git.example/",
		"https://git.example/alice/repo.git?token=secret",
		"https://git.example/alice/repo.git#fragment",
	} {
		if err := validateGitCloneURL(context.Background(), raw, resolver); err == nil {
			t.Errorf("expected clone URL %q to be rejected", raw)
		}
	}
}

func TestRedirectValidationRejectsPrivateTarget(t *testing.T) {
	client := newClient(fakeResolver{
		"public.example": {netip.MustParseAddr("93.184.216.34")},
		"internal":       {netip.MustParseAddr("10.0.0.5")},
	})
	redirectURL, err := url.Parse("https://internal/admin")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: redirectURL}
	err = client.CheckRedirect(req, []*http.Request{{URL: &url.URL{Scheme: "https", Host: "public.example"}}})
	if err == nil || !strings.Contains(err.Error(), "unsafe redirect target") {
		t.Fatalf("expected unsafe redirect rejection, got %v", err)
	}
}

func TestClientRejectsNonHTTPSBeforeNetwork(t *testing.T) {
	client := newClient(fakeResolver{"public.example": {netip.MustParseAddr("93.184.216.34")}})
	req, err := http.NewRequest(http.MethodGet, "http://public.example/avatar.png", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS policy error, got %v", err)
	}
}

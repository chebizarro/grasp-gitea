// Package safefetch provides SSRF-resistant outbound HTTP and Git URL validation.
package safefetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxRedirects = 10

type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type guard struct {
	resolver ipResolver
	dialer   net.Dialer
}

type guardedTransport struct {
	guard *guard
	base  http.RoundTripper
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata.
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// NewClient returns an HTTP client that permits only HTTPS requests and rejects
// every target whose DNS results include a private, loopback, link-local,
// metadata, multicast, unspecified, or otherwise reserved address.
//
// The same validation runs for the initial request and every redirect. The
// transport dials a previously validated literal address, so a second,
// unvalidated DNS lookup cannot bypass the guard. Callers should additionally
// use request contexts or set Client.Timeout for workload-specific deadlines.
func NewClient() *http.Client {
	return newClient(net.DefaultResolver)
}

func newClient(resolver ipResolver) *http.Client {
	g := &guard{
		resolver: resolver,
		dialer: net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           g.dialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: &guardedTransport{guard: g, base: transport},
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if err := g.validateURL(req.Context(), req.URL); err != nil {
			return fmt.Errorf("unsafe redirect target: %w", err)
		}
		return nil
	}
	return client
}

// ValidateHTTPSURL verifies that rawURL is an HTTPS URL whose current DNS
// results are all safe for public egress. HTTP callers should use NewClient as
// well, because validation must be repeated at dial time and after redirects.
func ValidateHTTPSURL(ctx context.Context, rawURL string) error {
	return validateHTTPSURL(ctx, rawURL, net.DefaultResolver)
}

// ValidateGitCloneURL validates a Nostr-supplied Git clone URL. Only public
// HTTPS URLs without credentials, query parameters, or fragments are accepted.
// Call this immediately before invoking Git. For complete DNS-rebinding
// resistance, deployments should also enforce the same policy at the network
// egress boundary.
func ValidateGitCloneURL(ctx context.Context, rawURL string) error {
	return validateGitCloneURL(ctx, rawURL, net.DefaultResolver)
}

func validateHTTPSURL(ctx context.Context, rawURL string, resolver ipResolver) error {
	u, err := parseURL(rawURL)
	if err != nil {
		return err
	}
	g := &guard{resolver: resolver}
	return g.validateURL(ctx, u)
}

func validateGitCloneURL(ctx context.Context, rawURL string, resolver ipResolver) error {
	u, err := parseURL(rawURL)
	if err != nil {
		return fmt.Errorf("invalid git clone URL: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid git clone URL: query parameters and fragments are not allowed")
	}
	if u.EscapedPath() == "" || u.EscapedPath() == "/" {
		return fmt.Errorf("invalid git clone URL: repository path is required")
	}
	g := &guard{resolver: resolver}
	if err := g.validateURL(ctx, u); err != nil {
		return fmt.Errorf("invalid git clone URL: %w", err)
	}
	return nil
}

func parseURL(rawURL string) (*url.URL, error) {
	if strings.TrimSpace(rawURL) != rawURL || rawURL == "" {
		return nil, fmt.Errorf("URL must be non-empty and contain no surrounding whitespace")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("only absolute HTTPS URLs are allowed")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL host is required")
	}
	if u.User != nil {
		return nil, fmt.Errorf("URL credentials are not allowed")
	}
	if u.Opaque != "" {
		return nil, fmt.Errorf("opaque URLs are not allowed")
	}
	return u, nil
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("nil outbound request")
	}
	if err := t.guard.validateURL(req.Context(), req.URL); err != nil {
		return nil, fmt.Errorf("unsafe outbound URL: %w", err)
	}
	return t.base.RoundTrip(req)
}

func (g *guard) validateURL(ctx context.Context, u *url.URL) error {
	if u == nil {
		return fmt.Errorf("nil URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("scheme %q is not allowed; HTTPS is required", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("URL host is required")
	}
	if u.User != nil {
		return fmt.Errorf("URL credentials are not allowed")
	}
	_, err := g.resolvePublicIPs(ctx, u.Hostname())
	return err
}

func (g *guard) resolvePublicIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if err := validateIP(ip); err != nil {
			return nil, fmt.Errorf("host %q: %w", host, err)
		}
		return []netip.Addr{ip}, nil
	}
	if strings.Contains(host, "%") {
		return nil, fmt.Errorf("IP zones are not allowed")
	}
	ips, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("host %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if err := validateIP(ip); err != nil {
			return nil, fmt.Errorf("host %q resolved to unsafe address %s: %w", host, ip, err)
		}
	}
	return ips, nil
}

func validateIP(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return fmt.Errorf("non-global-unicast address is not allowed")
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return fmt.Errorf("private, loopback, link-local, multicast, or unspecified address is not allowed")
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("reserved or metadata address is not allowed")
		}
	}
	return nil
}

func (g *guard) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split dial address %q: %w", address, err)
	}
	ips, err := g.resolvePublicIPs(ctx, host)
	if err != nil {
		return nil, err
	}

	var dialErrs []error
	for _, ip := range ips {
		if network == "tcp4" && !ip.Is4() {
			continue
		}
		if network == "tcp6" && ip.Is4() {
			continue
		}
		conn, dialErr := g.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		dialErrs = append(dialErrs, dialErr)
	}
	if len(dialErrs) == 0 {
		return nil, fmt.Errorf("host %q has no addresses for network %q", host, network)
	}
	return nil, fmt.Errorf("dial validated host %q: %w", host, errors.Join(dialErrs...))
}

package provisioner

import (
	"testing"

	"fiatjaf.com/nostr"
)

func TestFindCloneForServiceCanonicalNpubURL(t *testing.T) {
	graspURL := "https://grasp.sharegap.net"
	npub := "npub1owner"
	repoID := "repo one"

	tags := nostr.Tags{
		{"clone", "https://git.sharegap.net/some-org/repo-one.git"},
		{"clone", "https://grasp.sharegap.net/npub1owner/repo%20one.git"},
	}
	got, ok := findCloneForService(tags, graspURL, "https://legacy.example", npub, repoID)
	if !ok || got != "https://grasp.sharegap.net/npub1owner/repo%20one.git" {
		t.Fatalf("expected canonical clone URL match, got %q ok=%v", got, ok)
	}

	// NIP-34 permits multiple clone URLs in one tag. The service URL need not
	// be the first value.
	multiValue := nostr.Tags{
		{"clone",
			"https://relay.ngit.dev/npub1owner/repo%20one.git",
			"https://gitnostr.com/npub1owner/repo%20one.git",
			"https://grasp.sharegap.net/npub1owner/repo%20one.git",
		},
	}
	got, ok = findCloneForService(multiValue, graspURL, "https://legacy.example", npub, repoID)
	if !ok || got != "https://grasp.sharegap.net/npub1owner/repo%20one.git" {
		t.Fatalf("expected canonical clone URL in multi-value tag, got %q ok=%v", got, ok)
	}

	// Gitea /org/repo.git URL alone is NOT canonical when a grasp origin is set.
	giteaOnly := nostr.Tags{{"clone", "https://git.sharegap.net/some-org/repo-one.git"}}
	if _, ok := findCloneForService(giteaOnly, graspURL, "https://grasp.sharegap.net", npub, repoID); ok {
		t.Fatalf("expected org-form Gitea URL to be rejected as canonical")
	}

	// Legacy prefix fallback still works when no grasp origin configured.
	legacy := nostr.Tags{{"clone", "https://legacy.example/npub1owner/repo.git"}}
	if got, ok := findCloneForService(legacy, "", "https://legacy.example", npub, repoID); !ok || got == "" {
		t.Fatalf("expected legacy prefix fallback, got %q ok=%v", got, ok)
	}

	legacyMultiValue := nostr.Tags{{
		"clone",
		"https://example.invalid/npub1owner/repo.git",
		"https://legacy.example/npub1owner/repo.git",
	}}
	if got, ok := findCloneForService(legacyMultiValue, "", "https://legacy.example", npub, repoID); !ok || got == "" {
		t.Fatalf("expected legacy prefix in multi-value tag, got %q ok=%v", got, ok)
	}
}

func TestServiceRelayURLPrefersCanonical(t *testing.T) {
	tags := nostr.Tags{{"relays", "wss://grasp.sharegap.net"}}
	if !hasRelayForService(tags, "wss://grasp.sharegap.net") {
		t.Fatal("expected canonical relay to match")
	}
	if hasRelayForService(nostr.Tags{{"relays", "wss://relay.sharegap.net"}}, "wss://grasp.sharegap.net") {
		t.Fatal("expected non-canonical relay to be rejected")
	}
}

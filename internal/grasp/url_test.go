package grasp

import "testing"

func TestCanonicalCloneURL(t *testing.T) {
	got := CanonicalCloneURL("https://grasp.sharegap.net/", "npub1abc", "repo one")
	want := "https://grasp.sharegap.net/npub1abc/repo%20one.git"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if CanonicalCloneURL("", "npub1abc", "r") != "" {
		t.Fatal("expected empty when unconfigured")
	}
}

//go:build full

package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/relay"
)

const embeddedRelayTestSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeHostedRepoChecker map[string]struct{}

func (f fakeHostedRepoChecker) MappingExists(_ context.Context, npub string, repoID string) (bool, error) {
	_, ok := f[npub+"\x00"+repoID]
	return ok, nil
}

func TestEmbeddedRelayPolicyAcceptsCollaborationKindsReferencingHostedRepo(t *testing.T) {
	pubkey, err := derivePubHex(embeddedRelayTestSecretKey)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	pk, err := nostr.PubKeyFromHex(pubkey)
	if err != nil {
		t.Fatalf("owner pubkey: %v", err)
	}
	npub := nip19.EncodeNpub(pk)
	policy := makeEmbeddedRelayRejectPolicy(fakeHostedRepoChecker{npub + "\x00" + "repo1": {}}, nil)

	kinds := []nostr.Kind{
		relay.KindPatch,
		relay.KindPROpen,
		relay.KindPRUpdate,
		relay.KindIssue,
		relay.KindStatusOpen,
		relay.KindStatusApplied,
		relay.KindStatusClosed,
		relay.KindStatusDraft,
		relay.KindNIP22Comment,
	}
	for _, kind := range kinds {
		t.Run(kind.String(), func(t *testing.T) {
			ev := &nostr.Event{
				Kind: kind,
				Tags: nostr.Tags{{"a", "30617:" + pubkey + ":repo1"}},
			}
			reject, msg := policy(context.Background(), ev)
			if reject {
				t.Fatalf("expected kind %d referencing hosted repo to be accepted, rejected with %q", kind, msg)
			}
		})
	}
}

func TestEmbeddedRelayPolicyRejectsIssueWithoutHostedRepoReference(t *testing.T) {
	pubkey, err := derivePubHex(embeddedRelayTestSecretKey)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}

	policy := makeEmbeddedRelayRejectPolicy(fakeHostedRepoChecker{}, nil)
	ev := &nostr.Event{
		Kind: relay.KindIssue,
		Tags: nostr.Tags{{"a", "30617:" + pubkey + ":unknown"}},
	}
	reject, msg := policy(context.Background(), ev)
	if !reject {
		t.Fatal("expected issue without hosted repo reference to be rejected")
	}
	if msg == "" {
		t.Fatal("expected rejection message")
	}
}

func TestEmbeddedRelayPolicyAcceptsStatusReferencingStoredPatch(t *testing.T) {
	policy := makeEmbeddedRelayRejectPolicy(nil, func(_ context.Context, eventID string) (*nostr.Event, error) {
		if eventID == "patch-event" {
			return &nostr.Event{Kind: relay.KindPatch}, nil
		}
		return nil, nil
	})
	ev := &nostr.Event{
		Kind: relay.KindStatusApplied,
		Tags: nostr.Tags{{"e", "patch-event"}},
	}
	reject, msg := policy(context.Background(), ev)
	if reject {
		t.Fatalf("expected status referencing stored patch to be accepted, rejected with %q", msg)
	}
}

func TestEmbeddedRelayNIP11AdvertisesGRASPFields(t *testing.T) {
	rl := khatru.NewRelay()
	rl.Info.Name = "test relay"

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/nostr+json")
	rec := httptest.NewRecorder()
	graspNIP11Handler(rl, config.Config{}).ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode NIP-11: %v", err)
	}
	if got := doc["repo_acceptance_criteria"]; got == "" || got == nil {
		t.Fatalf("expected repo_acceptance_criteria, got %#v", got)
	}
	if _, ok := doc["curation"]; ok {
		t.Fatalf("curation should be omitted when not curated: %#v", doc["curation"])
	}

	supported, ok := doc["supported_grasps"].([]any)
	if !ok {
		t.Fatalf("supported_grasps has unexpected type/value: %#v", doc["supported_grasps"])
	}
	seen := map[string]bool{}
	for _, value := range supported {
		if s, ok := value.(string); ok {
			seen[s] = true
		}
	}
	if !seen["GRASP-01"] {
		t.Fatalf("expected GRASP-01 in supported_grasps, got %#v", supported)
	}
	// GRASP-02 must not be advertised until validated (beads phase1-t7j).
	if seen["GRASP-02"] {
		t.Fatalf("GRASP-02 must not be advertised before validation, got %#v", supported)
	}
}

func TestEmbeddedRelayNIP11IncludesCurationWhenAllowlisted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "application/nostr+json")
	rec := httptest.NewRecorder()
	graspNIP11Handler(khatru.NewRelay(), config.Config{PubkeyAllowlist: map[string]struct{}{"pk": {}}}).ServeHTTP(rec, req)

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode NIP-11: %v", err)
	}
	if got := doc["curation"]; got == "" || got == nil {
		t.Fatalf("expected curation for allowlisted relay, got %#v", got)
	}
}

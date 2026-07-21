// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	cascadia "git.sharegap.net/cascadia/cascadia-go"
	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/relay"
)

func TestIsRepoCIAllowed(t *testing.T) {
	svc := &Service{}

	// Empty allowlist — nothing allowed.
	svc.ciTriggerRepos = nil
	if svc.isRepoCIAllowed("alice", "myrepo") {
		t.Error("should not be allowed with empty allowlist")
	}

	// Wildcard — everything allowed.
	svc.ciTriggerRepos = []string{"*"}
	if !svc.isRepoCIAllowed("alice", "myrepo") {
		t.Error("should be allowed with wildcard")
	}
	if !svc.isRepoCIAllowed("bob", "other") {
		t.Error("wildcard should match any repo")
	}

	// Specific entries.
	svc.ciTriggerRepos = []string{"alice/myrepo", "bob/other"}
	if !svc.isRepoCIAllowed("alice", "myrepo") {
		t.Error("should be allowed with exact match")
	}
	if !svc.isRepoCIAllowed("bob", "other") {
		t.Error("should be allowed with exact match")
	}
	if svc.isRepoCIAllowed("alice", "notmyrepo") {
		t.Error("should not be allowed without match")
	}
	if svc.isRepoCIAllowed("charlie", "myrepo") {
		t.Error("should not match different owner")
	}
}

func TestBuildWorkflowRunEvent(t *testing.T) {
	privKey := nostr.GeneratePrivateKey()
	pubKey, err := nostr.GetPublicKey(privKey)
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}

	svc := &Service{
		bridgePrivKey: privKey,
		bridgePubKey:  pubKey,
	}

	ownerPubkey := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	repoID := "my-repo"
	commitSHA := "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	branch := "main"
	workflow := ".github/workflows/ci.yaml"
	relayHint := "wss://relay.example.com"

	ev, err := svc.buildWorkflowRunEvent(context.Background(), ownerPubkey, repoID, commitSHA, branch, workflow, relayHint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Kind != cascadia.ContextVMMethods["ci/workflow-run"].Kind {
		t.Errorf("expected canonical ContextVM kind, got %d", ev.Kind)
	}
	if ev.PubKey != pubKey {
		t.Errorf("expected pubkey %s, got %s", pubKey, ev.PubKey)
	}
	var request struct {
		JSONRPC string                           `json:"jsonrpc"`
		ID      string                           `json:"id"`
		Method  string                           `json:"method"`
		Params  cascadia.HiveCiWorkflowV1Payload `json:"params"`
	}
	if err := json.Unmarshal([]byte(ev.Content), &request); err != nil {
		t.Fatalf("decode ContextVM request: %v", err)
	}
	if request.JSONRPC != "2.0" || request.Method != "ci/workflow-run" {
		t.Fatalf("unexpected ContextVM request: %+v", request)
	}
	if request.ID == "" {
		t.Error("expected a request id")
	}
	if request.Params.Workflow != workflow || request.Params.Commit != commitSHA || request.Params.Branch != branch || request.Params.TriggeredBy != "push" {
		t.Errorf("unexpected workflow payload: %+v", request.Params)
	}
	if err := request.Params.Validate(); err != nil {
		t.Errorf("generated payload validation failed: %v", err)
	}

	// Verify tags.
	expectedA := "30617:" + ownerPubkey + ":" + repoID
	assertTag(t, ev, "a", expectedA)
	assertTag(t, ev, "p", ownerPubkey)
	assertTag(t, ev, "publisher", pubKey)
	assertTag(t, ev, "relay", relayHint)

	// Verify signature.
	ok, err := ev.CheckSignature()
	if err != nil || !ok {
		t.Error("event signature verification failed")
	}
}

func TestBuildWorkflowRunEventDifferentBranch(t *testing.T) {
	privKey := nostr.GeneratePrivateKey()
	pubKey, _ := nostr.GetPublicKey(privKey)
	svc := &Service{bridgePrivKey: privKey, bridgePubKey: pubKey}

	ev, err := svc.buildWorkflowRunEvent(context.Background(), "aabb", "repo1", "ccdd", "develop", ".github/workflows/test.yml", "wss://r.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertTag(t, ev, "publisher", pubKey)
	var request struct {
		Method string                           `json:"method"`
		Params cascadia.HiveCiWorkflowV1Payload `json:"params"`
	}
	if err := json.Unmarshal([]byte(ev.Content), &request); err != nil {
		t.Fatalf("decode ContextVM request: %v", err)
	}
	if request.Method != "ci/workflow-run" || request.Params.Branch != "develop" || request.Params.Workflow != ".github/workflows/test.yml" {
		t.Errorf("unexpected request: %+v", request)
	}
}

func TestBuildWorkflowRunEventHiveWorkflow(t *testing.T) {
	privKey := nostr.GeneratePrivateKey()
	pubKey, _ := nostr.GetPublicKey(privKey)
	svc := &Service{bridgePrivKey: privKey, bridgePubKey: pubKey}

	ev, err := svc.buildWorkflowRunEvent(
		context.Background(),
		"aabb", "repo1", "ccdd", "main",
		".hive/workflows/build.yaml", "wss://r.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertTag(t, ev, "publisher", pubKey)
	var request struct {
		Params cascadia.HiveCiWorkflowV1Payload `json:"params"`
	}
	if err := json.Unmarshal([]byte(ev.Content), &request); err != nil {
		t.Fatalf("decode ContextVM request: %v", err)
	}
	if request.Params.Workflow != ".hive/workflows/build.yaml" || request.Params.Branch != "main" {
		t.Errorf("unexpected payload: %+v", request.Params)
	}
}

func TestCIEnabledRequiresBothFlags(t *testing.T) {
	svc := &Service{}
	if svc.CIEnabled() {
		t.Error("should not be CI-enabled without bridge key")
	}

	svc.bridgePrivKey = "some-key"
	if svc.CIEnabled() {
		t.Error("should not be CI-enabled without ciEnabled flag")
	}

	svc.ciEnabled = true
	if !svc.CIEnabled() {
		t.Error("should be CI-enabled with both bridge key and ciEnabled")
	}
}

func TestEvTagValue(t *testing.T) {
	tags := nostr.Tags{
		{"d", "my-repo"},
		{"p", "abcdef"},
	}

	if v := evTagValue(tags, "d"); v != "my-repo" {
		t.Errorf("expected 'my-repo', got %q", v)
	}
	if v := evTagValue(tags, "p"); v != "abcdef" {
		t.Errorf("expected 'abcdef', got %q", v)
	}
	if v := evTagValue(tags, "missing"); v != "" {
		t.Errorf("expected empty, got %q", v)
	}
}

func TestEvTagValueEmptyTags(t *testing.T) {
	if v := evTagValue(nil, "d"); v != "" {
		t.Errorf("expected empty for nil tags, got %q", v)
	}
	if v := evTagValue(nostr.Tags{}, "d"); v != "" {
		t.Errorf("expected empty for empty tags, got %q", v)
	}
}

func TestWorkflowRunUsesGeneratedCanonicalBinding(t *testing.T) {
	method, ok := cascadia.ContextVMMethods["ci/workflow-run"]
	if !ok {
		t.Fatal("generated binding missing ci/workflow-run")
	}
	if relay.KindContextVMIntent != method.Kind || relay.KindContextVMIntent != cascadia.CAS_INTENT {
		t.Errorf("ContextVM kind drift: relay=%d method=%d generated=%d", relay.KindContextVMIntent, method.Kind, cascadia.CAS_INTENT)
	}
	if method.Schema != "hive.ci.workflow.v1" {
		t.Errorf("unexpected schema %q", method.Schema)
	}
}

func TestWorkflowDirsContainsExpectedPaths(t *testing.T) {
	expected := map[string]bool{
		".github/workflows": false,
		".hive/workflows":   false,
	}
	for _, dir := range workflowDirs {
		if _, ok := expected[dir]; ok {
			expected[dir] = true
		}
	}
	for dir, found := range expected {
		if !found {
			t.Errorf("workflowDirs missing expected directory %q", dir)
		}
	}
}

// ---------------------------------------------------------------------------
// Dedup cache tests
// ---------------------------------------------------------------------------

func TestCIDedupMarkSeen(t *testing.T) {
	d := newCIDedup()

	// First call: not seen yet.
	if d.MarkSeen("evt-1") {
		t.Error("first call should return false")
	}
	// Second call: already seen.
	if !d.MarkSeen("evt-1") {
		t.Error("second call should return true")
	}
	// Different ID: not seen.
	if d.MarkSeen("evt-2") {
		t.Error("different ID should not be seen")
	}
	if d.Len() != 2 {
		t.Errorf("expected 2 entries, got %d", d.Len())
	}
}

func TestCIDedupSweep(t *testing.T) {
	d := newCIDedup()

	// Insert entries with an artificially old timestamp.
	d.mu.Lock()
	for i := range dedupSweepThreshold {
		d.seen[fmt.Sprintf("old-%d", i)] = 0 // epoch — very old
	}
	d.mu.Unlock()

	if d.Len() != dedupSweepThreshold {
		t.Fatalf("expected %d entries, got %d", dedupSweepThreshold, d.Len())
	}

	// Insert a new entry; this triggers the sweep.
	d.MarkSeen("fresh")

	// All old entries should have been evicted; only "fresh" remains.
	if d.Len() != 1 {
		t.Errorf("expected 1 entry after sweep, got %d", d.Len())
	}
}

func TestSetCIConfigInitialisesDedup(t *testing.T) {
	svc := &Service{bridgePrivKey: "k"}
	if svc.ciDedup != nil {
		t.Error("ciDedup should be nil before SetCIConfig")
	}

	svc.SetCIConfig(true, []string{"*"})

	if svc.ciDedup == nil {
		t.Error("ciDedup should be initialised after SetCIConfig")
	}
	if !svc.ciEnabled {
		t.Error("ciEnabled should be true")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertTag(t *testing.T, ev *nostr.Event, key, expectedValue string) {
	t.Helper()
	v := evTagValue(ev.Tags, key)
	if v != expectedValue {
		t.Errorf("tag %q: expected %q, got %q", key, expectedValue, v)
	}
}

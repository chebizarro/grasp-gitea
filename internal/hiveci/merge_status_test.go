// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/loom"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type mergeRemoteDispatcher struct {
	unique         map[string]loom.DispatchRequest
	calls          int
	beforeDispatch func(loom.DispatchRequest) error
}

type mergeAuthorizer struct {
	authorized string
	err        error
}

func (a mergeAuthorizer) IsWorkflowAuthorAuthorized(_ context.Context, _ store.Mapping, author string) (bool, error) {
	return author == a.authorized, a.err
}

func (d *mergeRemoteDispatcher) Enabled() bool { return true }
func (d *mergeRemoteDispatcher) Dispatch(_ context.Context, req loom.DispatchRequest) (bool, error) {
	if d.beforeDispatch != nil {
		if err := d.beforeDispatch(req); err != nil {
			return true, err
		}
	}
	d.calls++
	if d.unique == nil {
		d.unique = make(map[string]loom.DispatchRequest)
	}
	d.unique[req.TriggerEnvelopeID+"\x00"+req.WorkflowPath] = req
	return true, nil
}

type mergeFixture struct {
	ctx             context.Context
	store           *store.SQLiteStore
	dbPath          string
	mapping         store.Mapping
	ownerPriv       string
	contributorPriv string
	repositoriesDir string
	repoPath        string
	root            *nostr.Event
	update          *nostr.Event
	baseCommit      string
	sourceCommit    string
	acceptedCommit  string
	stateCreatedAt  int64
}

func TestMergeStatusValidAuthorizedTriggerAndReplay(t *testing.T) {
	fx := newMergeFixture(t, true)
	remote := &mergeRemoteDispatcher{beforeDispatch: func(req loom.DispatchRequest) error {
		envelope, err := fx.store.GetMergeTriggerEnvelopeByStatusID(fx.ctx, req.StatusEventID)
		if err != nil {
			return fmt.Errorf("dispatch crossed boundary before durable envelope: %w", err)
		}
		if envelope.IdempotencyKey != req.TriggerEnvelopeID {
			return fmt.Errorf("dispatch envelope = %s, durable claim = %s", req.TriggerEnvelopeID, envelope.IdempotencyKey)
		}
		return nil
	}}
	runner := newMergeRunner(fx, remote)
	status := fx.statusEvent(t, fx.ownerPriv, true, fx.acceptedCommit, fx.stateCreatedAt+1)

	if err := runner.HandleEvent(fx.ctx, status, "wss://relay.test"); err != nil {
		t.Fatalf("valid merge status: %v", err)
	}
	if len(remote.unique) != 1 {
		t.Fatalf("unique dispatches = %d, want 1", len(remote.unique))
	}
	var req loom.DispatchRequest
	for _, request := range remote.unique {
		req = request
	}
	if req.PREventID != fx.update.ID.Hex() || req.StatusEventID != status.ID.Hex() ||
		req.CommitSHA != fx.acceptedCommit || req.SourceCommit != fx.sourceCommit || req.SourceTree == "" || req.PatchDigest == "" ||
		req.RepoAddress != fx.repoAddress() || req.PolicyVersion != mergeStatusPolicyVersion ||
		req.TriggerEnvelopeID == "" {
		t.Fatalf("dispatch is not bound to the merge envelope: %#v", req)
	}
	envelope, err := fx.store.GetMergeTriggerEnvelopeByStatusID(fx.ctx, status.ID.Hex())
	if err != nil {
		t.Fatalf("load envelope: %v", err)
	}
	if envelope.PREventID != fx.update.ID.Hex() || envelope.StatusEventID != status.ID.Hex() ||
		envelope.SourceCommit != fx.sourceCommit || envelope.AcceptedCommit != fx.acceptedCommit ||
		envelope.SourceTree != req.SourceTree || envelope.PatchDigest != req.PatchDigest ||
		envelope.RepoAddress != fx.repoAddress() || envelope.PolicyVersion != mergeStatusPolicyVersion {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}

	// Replays resume through the existing idempotent dispatch seam using the
	// same envelope identity. The fake records unique attempts by envelope/path.
	if err := runner.HandleEvent(fx.ctx, status, "wss://relay.other"); err != nil {
		t.Fatalf("replay merge status: %v", err)
	}
	if len(remote.unique) != 1 || remote.calls != 2 {
		t.Fatalf("replay unique=%d calls=%d, want one immutable attempt resumed", len(remote.unique), remote.calls)
	}

	// The same claim remains recoverable after reopening SQLite.
	if err := fx.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fx.store = reopened
	restarted := newMergeRunner(fx, remote)
	if err := restarted.HandleEvent(fx.ctx, status, ""); err != nil {
		t.Fatalf("restart replay: %v", err)
	}
	if len(remote.unique) != 1 {
		t.Fatalf("restart replay created %d unique triggers, want 1", len(remote.unique))
	}
}

func TestMergeStatusAcceptsConfiguredBridgeAuthor(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	bridge := newFakeSigner(t)
	runner := New(Config{Enabled: false, TriggerRepos: []string{"*"}}, fx.store, bridge, nil,
		fx.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	runner.SetRemoteDispatcher(remote, "remote")
	status := fx.statusEvent(t, bridge.priv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	if err := runner.HandleEvent(fx.ctx, status, ""); err != nil {
		t.Fatalf("bridge-authored merge status: %v", err)
	}
	if len(remote.unique) != 1 {
		t.Fatalf("bridge-authored status created %d triggers, want 1", len(remote.unique))
	}
}

func TestMergeStatusAcceptsRecursiveMaintainerAuthor(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	maintainerPriv := nostr.Generate().Hex()
	maintainerPub, _ := derivePubHex(maintainerPriv)
	runner := newMergeRunner(fx, remote)
	runner.SetWorkflowAuthorizer(mergeAuthorizer{authorized: maintainerPub})
	status := fx.statusEvent(t, maintainerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	if err := runner.HandleEvent(fx.ctx, status, ""); err != nil {
		t.Fatalf("maintainer-authored merge status: %v", err)
	}
	if len(remote.unique) != 1 {
		t.Fatalf("maintainer-authored status created %d triggers, want 1", len(remote.unique))
	}
}

func TestMergeStatusFailsClosedWhenMaintainerAuthorityUnavailable(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	maintainerPriv := nostr.Generate().Hex()
	runner := newMergeRunner(fx, remote)
	runner.SetWorkflowAuthorizer(mergeAuthorizer{err: errors.New("authority unavailable")})
	status := fx.statusEvent(t, maintainerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	err := runner.HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrUnauthorizedMergeStatus) {
		t.Fatalf("error = %v, want ErrUnauthorizedMergeStatus", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestMergeStatusStatusFirstRecoversAfterRestart(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	lateRoot := signMergeEventAt(t, fx.contributorPriv, relay.KindPROpen, nostr.Tags{
		{"a", fx.repoAddress()}, {"c", fx.sourceCommit}, {"clone", "https://git.example/repo.git"},
		{"branch-name", "feature"},
	}, "reviewed late", 350)
	if _, err := fx.store.RecordReflectedEvent(fx.ctx, store.ReflectedEvent{
		NostrEventID: lateRoot.ID.Hex(), GiteaRepoID: fx.mapping.GiteaRepoID,
		GiteaIndex: 8, HeadBranch: "feature", Kind: relay.KindPROpen,
	}); err != nil {
		t.Fatal(err)
	}
	status := signMergeEventAt(t, fx.ownerPriv, relay.KindStatusApplied, nostr.Tags{
		{"e", lateRoot.ID.Hex(), "", "root"}, {"a", fx.repoAddress()},
		{"p", fx.mapping.Pubkey}, {"p", lateRoot.PubKey.Hex()},
		{"merge-commit", fx.acceptedCommit}, {"r", fx.acceptedCommit},
	}, "merged", fx.stateCreatedAt+1)
	runner := newMergeRunner(fx, remote)
	if err := runner.HandleEvent(fx.ctx, status, "wss://relay.test"); !errors.Is(err, ErrMissingPRLinkage) {
		t.Fatalf("status-first error = %v, want ErrMissingPRLinkage", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
	pending, err := fx.store.ListPendingMergeStatuses(fx.ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].EventID != status.ID.Hex() {
		t.Fatalf("pending statuses = %#v, err=%v", pending, err)
	}

	if err := fx.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fx.store = reopened
	restarted := newMergeRunner(fx, remote)
	if err := restarted.persistReviewedPRRevision(fx.ctx, fx.mapping, lateRoot, fx.sourceCommit); err != nil {
		t.Fatalf("persist late root: %v", err)
	}
	if err := restarted.RecoverPendingMergeStatuses(fx.ctx); err != nil {
		t.Fatalf("recover pending: %v", err)
	}
	if len(remote.unique) != 1 {
		t.Fatalf("recovery created %d triggers, want 1", len(remote.unique))
	}
	if _, err := fx.store.GetMergeTriggerEnvelopeByStatusID(fx.ctx, status.ID.Hex()); err != nil {
		t.Fatalf("recovered envelope: %v", err)
	}
	pending, err = fx.store.ListPendingMergeStatuses(fx.ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after recovery = %#v, err=%v", pending, err)
	}
}

func TestReviewedPRUpdateRejectsPoisonedTips(t *testing.T) {
	fx := newMergeFixture(t, false)
	runner := newMergeRunner(fx, &mergeRemoteDispatcher{})
	makeUpdate := func(t *testing.T, priv string, createdAt int64) *nostr.Event {
		t.Helper()
		return signMergeEventAt(t, priv, relay.KindPRUpdate, nostr.Tags{
			{"a", fx.repoAddress()}, {"E", fx.root.ID.Hex()}, {"P", fx.root.PubKey.Hex()},
			{"c", fx.sourceCommit}, {"clone", "https://git.example/repo.git"},
		}, "", createdAt)
	}
	t.Run("attacker authored", func(t *testing.T) {
		update := makeUpdate(t, nostr.Generate().Hex(), 500)
		if _, err := fx.store.RecordReflectedEvent(fx.ctx, store.ReflectedEvent{
			NostrEventID: update.ID.Hex(), GiteaRepoID: fx.mapping.GiteaRepoID,
			GiteaIndex: 7, HeadBranch: "feature", Kind: relay.KindPRUpdate,
		}); err != nil {
			t.Fatal(err)
		}
		if err := runner.persistReviewedPRRevision(fx.ctx, fx.mapping, update, fx.sourceCommit); err == nil {
			t.Fatal("attacker-authored PR update was persisted")
		}
	})
	t.Run("not reflected", func(t *testing.T) {
		update := makeUpdate(t, fx.contributorPriv, 501)
		if err := runner.persistReviewedPRRevision(fx.ctx, fx.mapping, update, fx.sourceCommit); err == nil {
			t.Fatal("unreflected PR update was persisted")
		}
	})
	latest, err := fx.store.GetLatestReviewedPRRevision(fx.ctx, fx.root.ID.Hex(), fx.repoAddress())
	if err != nil {
		t.Fatal(err)
	}
	if latest.EventID != fx.root.ID.Hex() {
		t.Fatalf("poisoned latest revision = %s, want root %s", latest.EventID, fx.root.ID.Hex())
	}
}

func TestMergeStatusRejectsUnauthorizedAuthorBeforeDispatch(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	attacker := nostr.Generate().Hex()
	status := fx.statusEvent(t, attacker, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrUnauthorizedMergeStatus) {
		t.Fatalf("error = %v, want ErrUnauthorizedMergeStatus", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestUnauthorizedRepositoryStateCannotPoisonAcceptedSnapshot(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	runner := newMergeRunner(fx, remote)
	before, err := fx.store.GetAcceptedRepositoryState(fx.ctx, fx.repoAddress())
	if err != nil {
		t.Fatal(err)
	}
	attacker := nostr.Generate().Hex()
	poison := signMergeEventAt(t, attacker, relay.KindRepositoryState, nostr.Tags{
		{"d", fx.mapping.RepoID}, {"p", fx.mapping.Pubkey},
		{"HEAD", "ref: refs/heads/main"}, {"refs/heads/main", fx.sourceCommit},
	}, "", fx.stateCreatedAt+100)
	if err := runner.HandleEvent(fx.ctx, poison, ""); err != nil {
		t.Fatalf("unauthorized state handling: %v", err)
	}
	after, err := fx.store.GetAcceptedRepositoryState(fx.ctx, fx.repoAddress())
	if err != nil {
		t.Fatal(err)
	}
	if after.EventID != before.EventID {
		t.Fatalf("unauthorized state replaced accepted snapshot: before=%s after=%s", before.EventID, after.EventID)
	}
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+101)
	if err := runner.HandleEvent(fx.ctx, status, ""); err != nil {
		t.Fatalf("valid status after poison attempt: %v", err)
	}
	if len(remote.unique) != 1 {
		t.Fatalf("valid status created %d triggers, want 1", len(remote.unique))
	}
}

func TestMergeStatusRejectsMissingPRLinkageBeforeDispatch(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	status.Tags[0][1] = strings.Repeat("9", 64)
	resignMergeEvent(t, status, fx.ownerPriv)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrMissingPRLinkage) {
		t.Fatalf("error = %v, want ErrMissingPRLinkage", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestMergeStatusRejectsStaleAcceptedStateBeforeDispatch(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	// A later accepted state that names a different local tip makes the status
	// stale. Cross-kind timestamp order alone is deliberately not sufficient.
	fx.saveState(t, fx.sourceCommit, fx.stateCreatedAt+10)
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.sourceCommit, fx.stateCreatedAt+11)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrStaleMergeStatus) {
		t.Fatalf("error = %v, want ErrStaleMergeStatus", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestMergeStatusRejectsStatusPredatingAcceptedState(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	fx.saveState(t, fx.acceptedCommit, fx.stateCreatedAt+10)
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+9)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrStaleMergeStatus) {
		t.Fatalf("error = %v, want ErrStaleMergeStatus", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestMergeStatusRejectsSupersededRevisionBeforeDispatch(t *testing.T) {
	fx := newMergeFixture(t, true)
	remote := &mergeRemoteDispatcher{}
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrSupersededCommit) {
		t.Fatalf("error = %v, want ErrSupersededCommit", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestMergeStatusRejectsMissingGitObjectBeforeDispatch(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	missing := strings.Repeat("a", 40)
	fx.saveState(t, missing, fx.stateCreatedAt+10)
	status := fx.statusEvent(t, fx.ownerPriv, false, missing, fx.stateCreatedAt+11)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrMissingGitObject) {
		t.Fatalf("error = %v, want ErrMissingGitObject", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
	pending, pendingErr := fx.store.ListPendingMergeStatuses(fx.ctx, 10)
	if pendingErr != nil || len(pending) != 1 || pending[0].EventID != status.ID.Hex() ||
		!strings.Contains(pending[0].LastError, ErrMissingGitObject.Error()) {
		t.Fatalf("missing object pending state = %#v, err=%v", pending, pendingErr)
	}
}

func TestMergeStatusRejectsForcePushAmbiguityBeforeDispatch(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	// Replace the immutable reviewed source with a real but different commit;
	// it is not the merge's unique second parent.
	otherRoot := signMergeEventAt(t, fx.contributorPriv, relay.KindPROpen, nostr.Tags{
		{"a", fx.repoAddress()}, {"c", fx.baseCommit}, {"clone", "https://git.example/repo.git"},
	}, "", int64(fx.root.CreatedAt)+1)
	encoded, _ := json.Marshal(otherRoot)
	if err := fx.store.SaveReviewedPRRevision(fx.ctx, store.ReviewedPRRevision{
		EventID: otherRoot.ID.Hex(), RootEventID: otherRoot.ID.Hex(), RepoAddress: fx.repoAddress(),
		Kind: relay.KindPROpen, AuthorPubkey: otherRoot.PubKey.Hex(), SourceCommit: fx.baseCommit,
		EventCreatedAt: int64(otherRoot.CreatedAt), EventJSON: string(encoded),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.RecordReflectedEvent(fx.ctx, store.ReflectedEvent{
		NostrEventID: otherRoot.ID.Hex(), GiteaRepoID: fx.mapping.GiteaRepoID,
		GiteaIndex: 99, HeadBranch: "feature", Kind: relay.KindPROpen,
	}); err != nil {
		t.Fatal(err)
	}
	fx.root = otherRoot
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
	if !errors.Is(err, ErrForcePushAmbiguity) {
		t.Fatalf("error = %v, want ErrForcePushAmbiguity", err)
	}
	assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
}

func TestMergeStatusRejectsMalformedTagsBeforeDispatch(t *testing.T) {
	tests := map[string]func(*nostr.Event){
		"missing root": func(ev *nostr.Event) { ev.Tags = ev.Tags[1:] },
		"duplicate root": func(ev *nostr.Event) {
			ev.Tags = append(ev.Tags, nostr.Tag{"e", ev.Tags[0][1], "", "root"})
		},
		"unmarked event reference": func(ev *nostr.Event) {
			ev.Tags = append(ev.Tags, nostr.Tag{"e", strings.Repeat("7", 64)})
		},
		"duplicate repository": func(ev *nostr.Event) {
			ev.Tags = append(ev.Tags, nostr.Tag{"a", ev.Tags[1][1]})
		},
		"missing recipients": func(ev *nostr.Event) {
			ev.Tags = append(ev.Tags[:2], ev.Tags[4:]...)
		},
		"missing matching r": func(ev *nostr.Event) {
			ev.Tags = ev.Tags[:len(ev.Tags)-1]
		},
		"duplicate merge commit": func(ev *nostr.Event) {
			ev.Tags = append(ev.Tags, nostr.Tag{"merge-commit", ev.Tags[3][1]})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fx := newMergeFixture(t, false)
			remote := &mergeRemoteDispatcher{}
			status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
			mutate(status)
			resignMergeEvent(t, status, fx.ownerPriv)
			err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, "")
			if !errors.Is(err, ErrMalformedMergeStatus) {
				t.Fatalf("error = %v, want ErrMalformedMergeStatus", err)
			}
			assertNoMergeTrigger(t, fx, remote, status.ID.Hex())
		})
	}
}

func TestSyntheticCanonicalKind1631Fixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "kind-1631-merged.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ev nostr.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != relay.KindStatusApplied {
		t.Fatalf("kind = %d, want relay.KindStatusApplied", ev.Kind)
	}
	tags, err := parseMergeStatusTags(ev.Tags)
	if err != nil {
		t.Fatalf("parse synthetic fixture: %v", err)
	}
	if tags.rootID == "" || tags.replyID == "" || tags.mergeCommit == "" || tags.repoAddress == "" {
		t.Fatalf("incomplete fixture tags: %#v", tags)
	}
}

func TestRecordedCanonicalKind1631Fixtures(t *testing.T) {
	events := readRecordedKind1631Events(t)
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	runner := newMergeRunner(fx, remote)
	parsedMergeStatuses := 0
	amberIngests := 0

	for i := range events {
		ev := &events[i]
		t.Run(ev.ID.Hex()[:12], func(t *testing.T) {
			if ev.Kind != relay.KindStatusApplied {
				t.Fatalf("kind = %d, want relay.KindStatusApplied", ev.Kind)
			}
			if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
				t.Fatalf("recorded canonical event signature: %v", err)
			}

			repoAddress, err := strictRepoAddress(ev.Tags)
			if err != nil {
				t.Fatalf("recorded repository address: %v", err)
			}
			_, repoID, ok := parseRepoAddr(repoAddress)
			if !ok {
				t.Fatalf("parse repository address %q", repoAddress)
			}

			var rootID, replyID string
			for _, tag := range ev.Tags {
				if len(tag) < 4 || tag[0] != "e" {
					continue
				}
				switch tag[3] {
				case "root":
					rootID = tag[1]
				case "reply":
					replyID = tag[1]
				}
			}
			if !validEventIDString(rootID) {
				t.Fatalf("invalid recorded root thread: %q", rootID)
			}
			if quoted := tagValue(ev.Tags, "q"); quoted != "" && quoted != rootID {
				t.Fatalf("quoted proposal = %s, root = %s", quoted, rootID)
			}

			mergeCommit := tagValue(ev.Tags, "merge-commit-id")
			if mergeCommit == "" {
				mergeCommit = tagValue(ev.Tags, "merge-commit")
			}
			if mergeCommit == "" {
				return
			}
			parsedMergeStatuses++
			parsed, err := parseMergeStatusTags(ev.Tags)
			if err != nil {
				t.Fatalf("parse recorded canonical merge status: %v", err)
			}
			if parsed.repoAddress != repoAddress || parsed.rootID != rootID || parsed.replyID != replyID || parsed.mergeCommit != mergeCommit {
				t.Fatalf("parsed tags = %#v, want repo=%s root=%s reply=%s commit=%s",
					parsed, repoAddress, rootID, replyID, mergeCommit)
			}

			matchedR := false
			for _, tag := range ev.Tags {
				if len(tag) >= 2 && tag[0] == "r" && tag[1] == mergeCommit {
					matchedR = true
				}
			}
			if !matchedR {
				t.Fatalf("merge commit %s has no matching r tag", mergeCommit)
			}

			if repoID == "Amber" {
				amberIngests++
				err := runner.HandleEvent(fx.ctx, ev, "wss://relay.sharegap.net")
				want := fmt.Sprintf("%s: repository %s is not provisioned", ErrMissingPRLinkage, repoAddress)
				if !errors.Is(err, ErrMissingPRLinkage) || err.Error() != want {
					t.Fatalf("ingest error = %v, want %q", err, want)
				}
				assertNoMergeTrigger(t, fx, remote, ev.ID.Hex())
			}
		})
	}
	if parsedMergeStatuses != 15 {
		t.Fatalf("parsed merge statuses = %d, want 15", parsedMergeStatuses)
	}
	if amberIngests != 11 {
		t.Fatalf("Amber ingest attempts = %d, want 11", amberIngests)
	}
}

func TestRecordedCanonicalKind1631FailsClosedOnAuthorization(t *testing.T) {
	events := readRecordedKind1631Events(t)
	var recorded *nostr.Event
	var tags mergeStatusTags
	for i := range events {
		parsed, err := parseMergeStatusTags(events[i].Tags)
		if err == nil && strings.HasSuffix(parsed.repoAddress, ":Amber") {
			recorded = &events[i]
			tags = parsed
			break
		}
	}
	if recorded == nil {
		t.Fatal("recorded Amber merge status not found")
	}

	fx := newMergeFixture(t, false)
	ownerPub, repoID, ok := parseRepoAddr(tags.repoAddress)
	if !ok {
		t.Fatalf("parse recorded repository address %q", tags.repoAddress)
	}
	if err := fx.store.UpsertMapping(fx.ctx, store.Mapping{
		Npub: "npub1recorded", RepoID: repoID, Pubkey: ownerPub, Owner: "recorded", RepoName: repoID,
		GiteaRepoID: 84, CloneURL: "https://git.example/recorded/Amber.git", SourceEvent: "recorded", HookInstalled: true,
	}); err != nil {
		t.Fatal(err)
	}

	remote := &mergeRemoteDispatcher{}
	runner := newMergeRunner(fx, remote)
	runner.SetWorkflowAuthorizer(mergeAuthorizer{})
	err := runner.HandleEvent(fx.ctx, recorded, "wss://relay.sharegap.net")
	want := fmt.Sprintf("%s: signer %s", ErrUnauthorizedMergeStatus, recorded.PubKey.Hex())
	if !errors.Is(err, ErrUnauthorizedMergeStatus) || err.Error() != want {
		t.Fatalf("ingest error = %v, want %q", err, want)
	}
	assertNoMergeTrigger(t, fx, remote, recorded.ID.Hex())
}

func readRecordedKind1631Events(t *testing.T) []nostr.Event {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "recorded-kind-1631.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var events []nostr.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var ev nostr.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("decode recorded event line %d: %v", len(events)+1, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 20 {
		t.Fatalf("recorded events = %d, want 20", len(events))
	}
	return events
}

func newMergeRunner(fx *mergeFixture, remote *mergeRemoteDispatcher) *Runner {
	runner := New(Config{Enabled: false, TriggerRepos: []string{"*"}}, fx.store, nil, nil,
		fx.repositoriesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	runner.SetRemoteDispatcher(remote, "remote")
	return runner
}

func newMergeFixture(t *testing.T, withUpdate bool) *mergeFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "merge.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ownerPriv := nostr.Generate().Hex()
	ownerPub, _ := derivePubHex(ownerPriv)
	contributorPriv := nostr.Generate().Hex()
	mapping := store.Mapping{
		Npub: "npub1owner", RepoID: "repo1", Pubkey: ownerPub, Owner: "org1", RepoName: "repo1",
		GiteaRepoID: 42, CloneURL: "https://git.example/org1/repo1.git", SourceEvent: "seed", HookInstalled: true,
	}
	announcement := signMergeEventAt(t, ownerPriv, relay.KindRepositoryAnnouncement,
		nostr.Tags{{"d", mapping.RepoID}}, "", 100)
	announcementJSON, _ := json.Marshal(announcement)
	mapping.AnnouncementEventJSON = string(announcementJSON)
	if err := st.UpsertMapping(ctx, mapping); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAnnouncementEvent(ctx, mapping.Npub, mapping.RepoID, string(announcementJSON), announcement.ID.Hex()); err != nil {
		t.Fatal(err)
	}

	work := filepath.Join(dir, "work")
	repositoriesDir := filepath.Join(dir, "git", "repositories")
	repoPath := filepath.Join(repositoriesDir, mapping.Owner, mapping.RepoName+".git")
	hiveGit(t, dir, "init", "-b", "main", work)
	if err := os.MkdirAll(filepath.Join(work, ".gitea", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".gitea", "workflows", "deploy.yml"),
		[]byte("name: deploy\non: [push]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo deploy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, work, "add", ".")
	hiveGit(t, work, "commit", "-m", "base")
	base := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	hiveGit(t, work, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(work, "feature.txt"), []byte("reviewed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, work, "add", "feature.txt")
	hiveGit(t, work, "commit", "-m", "feature root")
	rootSource := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	source := rootSource
	if withUpdate {
		if err := os.WriteFile(filepath.Join(work, "feature.txt"), []byte("reviewed update\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		hiveGit(t, work, "add", "feature.txt")
		hiveGit(t, work, "commit", "-m", "feature update")
		source = strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	}
	hiveGit(t, work, "checkout", "main")
	if err := os.WriteFile(filepath.Join(work, "main.txt"), []byte("main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, work, "add", "main.txt")
	hiveGit(t, work, "commit", "-m", "main advance")
	hiveGit(t, work, "merge", "--no-ff", "feature", "-m", "merge feature")
	accepted := strings.TrimSpace(hiveGitOutput(t, work, "rev-parse", "HEAD"))
	if err := os.MkdirAll(filepath.Dir(repoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	hiveGit(t, dir, "clone", "--bare", work, repoPath)

	fx := &mergeFixture{ctx: ctx, store: st, dbPath: dbPath, mapping: mapping, ownerPriv: ownerPriv,
		contributorPriv: contributorPriv, repositoriesDir: repositoriesDir, repoPath: repoPath,
		baseCommit: base, sourceCommit: source, acceptedCommit: accepted, stateCreatedAt: 400}
	root := signMergeEventAt(t, contributorPriv, relay.KindPROpen, nostr.Tags{
		{"a", fx.repoAddress()}, {"c", rootSource}, {"clone", "https://git.example/repo.git"}, {"branch-name", "feature"},
	}, "review", 200)
	fx.root = root
	fx.saveRevision(t, root, root.ID.Hex(), rootSource)
	if _, err := st.RecordReflectedEvent(ctx, store.ReflectedEvent{
		NostrEventID: root.ID.Hex(), GiteaRepoID: mapping.GiteaRepoID, GiteaIndex: 7,
		HeadBranch: "feature", Kind: relay.KindPROpen,
	}); err != nil {
		t.Fatal(err)
	}
	if withUpdate {
		update := signMergeEventAt(t, contributorPriv, relay.KindPRUpdate, nostr.Tags{
			{"a", fx.repoAddress()}, {"E", root.ID.Hex()}, {"P", root.PubKey.Hex()},
			{"c", source}, {"clone", "https://git.example/repo.git"},
		}, "", 300)
		fx.update = update
		fx.saveRevision(t, update, root.ID.Hex(), source)
	}
	fx.saveState(t, accepted, fx.stateCreatedAt)
	return fx
}

func (fx *mergeFixture) repoAddress() string {
	return "30617:" + fx.mapping.Pubkey + ":" + fx.mapping.RepoID
}

func (fx *mergeFixture) saveRevision(t *testing.T, ev *nostr.Event, rootID, commit string) {
	t.Helper()
	encoded, _ := json.Marshal(ev)
	if err := fx.store.SaveReviewedPRRevision(fx.ctx, store.ReviewedPRRevision{
		EventID: ev.ID.Hex(), RootEventID: rootID, RepoAddress: fx.repoAddress(), Kind: int(ev.Kind),
		AuthorPubkey: ev.PubKey.Hex(), SourceCommit: commit, EventCreatedAt: int64(ev.CreatedAt),
		EventJSON: string(encoded),
	}); err != nil {
		t.Fatal(err)
	}
}

func (fx *mergeFixture) saveState(t *testing.T, commit string, createdAt int64) {
	t.Helper()
	state := signMergeEventAt(t, fx.ownerPriv, relay.KindRepositoryState, nostr.Tags{
		{"d", fx.mapping.RepoID}, {"HEAD", "ref: refs/heads/main"}, {"refs/heads/main", commit},
	}, "", createdAt)
	encoded, _ := json.Marshal(state)
	if err := fx.store.SaveAcceptedRepositoryState(fx.ctx, store.AcceptedRepositoryState{
		RepoAddress: fx.repoAddress(), EventID: state.ID.Hex(), AuthorPubkey: state.PubKey.Hex(),
		EventCreatedAt: int64(state.CreatedAt), EventJSON: string(encoded),
	}); err != nil {
		t.Fatal(err)
	}
}

func (fx *mergeFixture) statusEvent(t *testing.T, priv string, reply bool, mergeCommit string, createdAt int64) *nostr.Event {
	t.Helper()
	tags := nostr.Tags{{"e", fx.root.ID.Hex(), "", "root"}, {"a", fx.repoAddress()}, {"p", fx.mapping.Pubkey}, {"p", fx.root.PubKey.Hex()}}
	if reply && fx.update != nil {
		tags = append(tags, nostr.Tag{"e", fx.update.ID.Hex(), "", "reply"})
	}
	tags = append(tags, nostr.Tag{"merge-commit", mergeCommit}, nostr.Tag{"r", mergeCommit})
	return signMergeEventAt(t, priv, relay.KindStatusApplied, tags, "merged", createdAt)
}

func assertNoMergeTrigger(t *testing.T, fx *mergeFixture, remote *mergeRemoteDispatcher, statusID string) {
	t.Helper()
	if remote.calls != 0 || len(remote.unique) != 0 {
		t.Fatalf("rejected status crossed dispatch boundary: calls=%d unique=%d", remote.calls, len(remote.unique))
	}
	if _, err := fx.store.GetMergeTriggerEnvelopeByStatusID(fx.ctx, statusID); err == nil {
		t.Fatal("rejected status persisted a trigger envelope")
	}
}

func signMergeEventAt(t *testing.T, priv string, kind int, tags nostr.Tags, content string, createdAt int64) *nostr.Event {
	t.Helper()
	pub, err := derivePubHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	ev := &nostr.Event{PubKey: nostr.MustPubKeyFromHex(pub), Kind: nostr.Kind(kind), CreatedAt: nostr.Timestamp(createdAt), Tags: tags, Content: content}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatal(err)
	}
	return ev
}

func resignMergeEvent(t *testing.T, ev *nostr.Event, priv string) {
	t.Helper()
	ev.ID = nostr.ID{}
	ev.Sig = [64]byte{}
	if err := ev.Sign(mustSK(priv)); err != nil {
		t.Fatal(err)
	}
}

func TestMergeEnvelopeSourceTreeMatchesGitObject(t *testing.T) {
	fx := newMergeFixture(t, false)
	remote := &mergeRemoteDispatcher{}
	status := fx.statusEvent(t, fx.ownerPriv, false, fx.acceptedCommit, fx.stateCreatedAt+1)
	if err := newMergeRunner(fx, remote).HandleEvent(fx.ctx, status, ""); err != nil {
		t.Fatal(err)
	}
	envelope, err := fx.store.GetMergeTriggerEnvelopeByStatusID(fx.ctx, status.ID.Hex())
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(hiveGitOutput(t, "", "--git-dir", fx.repoPath, "rev-parse", fx.sourceCommit+"^{tree}"))
	if envelope.SourceTree != want {
		t.Fatalf("source tree = %s, want %s", envelope.SourceTree, want)
	}
}

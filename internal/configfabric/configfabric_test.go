package configfabric

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	cascadia "git.sharegap.net/cascadia/cascadia-nips/generated/go"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/policy"
)

type signingCapturePublisher struct {
	key    nostr.SecretKey
	events []nostr.Event
}

func (p *signingCapturePublisher) PublishEvent(_ context.Context, ev *nostr.Event) error {
	copy := *ev
	if err := copy.Sign(p.key); err != nil {
		return err
	}
	p.events = append(p.events, copy)
	return nil
}

func fabricStore(t *testing.T, author nostr.PubKey) (*policy.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := policy.Open(path, config.Config{
		RelayURLs: []string{"wss://relay.example"}, HookRelayURL: "wss://hook.example",
		ProfileSyncInterval: 10 * time.Minute, ProfileSyncWorkers: 4, HiveCIJobTimeoutMinutes: 15,
		ConfigTrustedAuthors: []string{author.Hex()}, ConfigScope: "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

func desiredEvent(t *testing.T, key nostr.SecretKey, policyName string, version int64, policyJSON string) *nostr.Event {
	t.Helper()
	schema := "cascadia.config." + policyName + ".v1"
	body := `{"service_id":"grasp-bridge","scope":"prod","version":` + jsonInt(version) + `,"schema":"` + schema + `","policy":` + policyJSON + `}`
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: nostr.Kind(cascadia.NIP78_APP_DATA), Tags: nostr.Tags{
		{"d", "service:grasp-bridge:" + policyName}, {"service", "grasp-bridge"}, {"scope", "prod"},
		{"version", jsonInt(version)}, {"schema", schema},
	}, Content: body}
	if err := ev.Sign(key); err != nil {
		t.Fatal(err)
	}
	return ev
}

func jsonInt(v int64) string { return strconv.FormatInt(v, 10) }

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestKind30078PersistsBeforeHotApplyAndEmitsSignedAppliedStatus(t *testing.T) {
	author := nostr.Generate()
	store, path := fabricStore(t, author.Public())
	publisher := &signingCapturePublisher{key: nostr.Generate()}
	manager := New(store, publisher, testLogger())
	changes := store.Changes()
	ev := desiredEvent(t, author, "provision", 2, `{"rate_limit_per_hour":77}`)
	if err := manager.HandleEvent(context.Background(), ev, "wss://relay.example"); err != nil {
		t.Fatal(err)
	}

	select {
	case <-changes:
	default:
		t.Fatal("hot snapshot was not published")
	}
	if got := store.Current().ProvisionRateLimit; got != 77 {
		t.Fatalf("hot-applied rate limit = %d", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted policy.Document
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Provision.RateLimitPerHour != 77 {
		t.Fatal("snapshot applied before candidate was durable")
	}
	coordinate := author.Public().Hex() + "|prod|service:grasp-bridge:provision"
	if got := persisted.ConfigFabric.Accepted[coordinate]; got.EventID != ev.ID.Hex() || got.Version != 2 {
		t.Fatalf("persisted accepted metadata = %#v", got)
	}

	if len(publisher.events) != 1 {
		t.Fatalf("status events = %d", len(publisher.events))
	}
	status := publisher.events[0]
	if status.Kind != nostr.Kind(cascadia.CAS_CP_STATE) || status.Tags.Find("status")[1] != "applied" {
		t.Fatalf("unexpected status event: %#v", status)
	}
	if err := nostrverify.ValidateEventIDAndSignature(&status); err != nil {
		t.Fatalf("status signature: %v", err)
	}
	var payload cascadia.CascadiaConfigStatusV1Payload
	if err := json.Unmarshal([]byte(status.Content), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.EffectiveVersion != 2 || payload.LastAppliedEventId != ev.ID.Hex() || payload.ConfigEventId != ev.ID.Hex() {
		t.Fatalf("status payload = %#v", payload)
	}
}

func TestKind30078RejectsUntrustedBadSignatureWrongTargetAndSchema(t *testing.T) {
	trusted := nostr.Generate()
	store, _ := fabricStore(t, trusted.Public())
	publisher := &signingCapturePublisher{key: nostr.Generate()}
	manager := New(store, publisher, testLogger())

	tests := []struct {
		name   string
		mutate func(*nostr.Event)
	}{
		{"bad author", func(ev *nostr.Event) {
			*ev = *desiredEvent(t, nostr.Generate(), "provision", 2, `{"rate_limit_per_hour":9}`)
		}},
		{"bad signature", func(ev *nostr.Event) { ev.Content += " " }},
		{"wrong service", func(ev *nostr.Event) {
			ev.Tags[0][1] = "service:other:provision"
			ev.Tags[1][1] = "other"
			_ = ev.Sign(trusted)
		}},
		{"wrong schema", func(ev *nostr.Event) { ev.Tags[4][1] = "cascadia.config.other.v1"; _ = ev.Sign(trusted) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := desiredEvent(t, trusted, "provision", 2, `{"rate_limit_per_hour":9}`)
			tc.mutate(ev)
			before := len(publisher.events)
			if err := manager.HandleEvent(context.Background(), ev, "relay"); err == nil {
				t.Fatal("invalid event accepted")
			}
			if store.Current().ProvisionRateLimit == 9 {
				t.Fatal("rejected event changed live policy")
			}
			if len(publisher.events) != before+1 {
				t.Fatal("rejection status was not emitted")
			}
			status := publisher.events[len(publisher.events)-1]
			if err := nostrverify.ValidateEventIDAndSignature(&status); err != nil {
				t.Fatal(err)
			}
			var payload cascadia.CascadiaConfigStatusV1Payload
			if err := json.Unmarshal([]byte(status.Content), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Status != "rejected" || payload.Reason == "" || payload.EffectiveVersion != 1 {
				t.Fatalf("rejection payload = %#v", payload)
			}
		})
	}
}

func TestKind30078RejectsStaleVersionAndKeepsLastValidProjection(t *testing.T) {
	author := nostr.Generate()
	store, path := fabricStore(t, author.Public())
	publisher := &signingCapturePublisher{key: nostr.Generate()}
	manager := New(store, publisher, testLogger())
	first := desiredEvent(t, author, "provision", 3, `{"rate_limit_per_hour":31}`)
	if err := manager.HandleEvent(context.Background(), first, "relay"); err != nil {
		t.Fatal(err)
	}
	persistedBefore, _ := os.ReadFile(path)
	stale := desiredEvent(t, author, "provision", 3, `{"rate_limit_per_hour":99}`)
	if err := manager.HandleEvent(context.Background(), stale, "relay"); err == nil || !strings.Contains(err.Error(), "does not advance") {
		t.Fatalf("stale rejection = %v", err)
	}
	persistedAfter, _ := os.ReadFile(path)
	if string(persistedAfter) != string(persistedBefore) || store.Current().ProvisionRateLimit != 31 {
		t.Fatal("stale candidate replaced last valid projection")
	}
	var payload cascadia.CascadiaConfigStatusV1Payload
	_ = json.Unmarshal([]byte(publisher.events[len(publisher.events)-1].Content), &payload)
	if payload.Status != "rejected" || payload.EffectiveVersion != 3 || payload.LastAppliedEventId != first.ID.Hex() {
		t.Fatalf("stale status = %#v", payload)
	}
}

func TestFilterTargetsTrustedAuthorsAndEverySupportedDTag(t *testing.T) {
	author := nostr.Generate()
	store, _ := fabricStore(t, author.Public())
	filter := New(store, nil, testLogger()).Filter()
	if len(filter.Kinds) != 1 || filter.Kinds[0] != nostr.Kind(cascadia.NIP78_APP_DATA) {
		t.Fatalf("kinds = %v", filter.Kinds)
	}
	if len(filter.Authors) != 1 || filter.Authors[0] != author.Public() {
		t.Fatalf("authors = %v", filter.Authors)
	}
	if len(filter.Tags["d"]) != len(policy.SupportedDesiredPolicies()) {
		t.Fatalf("d tags = %v", filter.Tags["d"])
	}
}

func TestEnvSeedImportStatusIsSignedAndAuditable(t *testing.T) {
	author := nostr.Generate()
	store, path := fabricStore(t, author.Public())
	seed, justSeeded := store.SeedImport()
	if !justSeeded || seed == nil || seed.AuthorizedBy != "local-bootstrap" || len(seed.ConsideredVariables) == 0 {
		t.Fatalf("seed audit = %#v, justSeeded=%v", seed, justSeeded)
	}
	publisher := &signingCapturePublisher{key: nostr.Generate()}
	if err := New(store, publisher, testLogger()).PublishEnvSeedStatus(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	if len(publisher.events) != 1 {
		t.Fatal("seed status not emitted")
	}
	if err := nostrverify.ValidateEventIDAndSignature(&publisher.events[0]); err != nil {
		t.Fatal(err)
	}
	if current, _ := store.SeedImport(); current == nil || !current.StatusPublished {
		t.Fatal("successful seed status publication was not durably recorded")
	}
	if !strings.Contains(publisher.events[0].Content, seed.AuditID) || !strings.Contains(publisher.events[0].Content, "considered_variables") {
		t.Fatal("seed status does not describe the imported projection")
	}
	reopened, err := policy.Open(path, config.Config{ConfigTrustedAuthors: []string{nostr.Generate().Public().Hex()}, ConfigScope: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	current, justSeeded := reopened.SeedImport()
	if justSeeded || current == nil || !current.StatusPublished {
		t.Fatalf("reopened seed audit = %#v, justSeeded=%v", current, justSeeded)
	}
}

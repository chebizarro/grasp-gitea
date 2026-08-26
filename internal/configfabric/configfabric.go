package configfabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	cascadia "git.sharegap.net/cascadia/cascadia-nips/generated/go"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/policy"
)

const (
	serviceID    = "grasp-bridge"
	statusSchema = "cascadia.config.status.v1"
)

type Publisher interface {
	PublishEvent(context.Context, *nostr.Event) error
}

type Manager struct {
	store     *policy.Store
	publisher Publisher
	logger    *slog.Logger
}

func New(store *policy.Store, publisher Publisher, logger *slog.Logger) *Manager {
	return &Manager{store: store, publisher: publisher, logger: logger}
}

type secretReference struct {
	Provider string `json:"provider"`
	Ref      string `json:"ref"`
}

type envelope struct {
	ServiceID  string                     `json:"service_id"`
	Scope      string                     `json:"scope"`
	Version    int64                      `json:"version"`
	Schema     string                     `json:"schema"`
	Policy     json.RawMessage            `json:"policy"`
	SecretRefs map[string]secretReference `json:"secret_refs,omitempty"`
}

type candidate struct {
	policyName string
	dTag       string
	scope      string
	schema     string
	version    int64
	eventID    string
	author     string
	policy     json.RawMessage
}

func (m *Manager) Filter() nostr.Filter {
	var authors []nostr.PubKey
	var dTags []string
	if snapshot := m.store.Current(); snapshot != nil {
		for _, raw := range snapshot.ConfigTrustedAuthors {
			if pk, err := nostr.PubKeyFromHex(raw); err == nil {
				authors = append(authors, pk)
			}
		}
	}
	for _, name := range policy.SupportedDesiredPolicies() {
		dTags = append(dTags, "service:"+serviceID+":"+name)
	}
	return nostr.Filter{Kinds: []nostr.Kind{nostr.Kind(cascadia.NIP78_APP_DATA)}, Authors: authors, Tags: nostr.TagMap{"d": dTags}}
}

func (m *Manager) HandleEvent(ctx context.Context, ev *nostr.Event, _ string) error {
	candidate, err := m.validate(ev)
	if err == nil {
		err = m.store.ApplyDesired(policy.DesiredUpdate{
			Author: candidate.author, Scope: candidate.scope, DTag: candidate.dTag,
			PolicyName: candidate.policyName, Schema: candidate.schema,
			Version: candidate.version, EventID: candidate.eventID, AppliedAt: time.Now(),
		}, candidate.policy)
	}
	if err != nil {
		reason := safeReason(err)
		if publishErr := m.publishStatus(ctx, rejectionCandidate(ev, candidate, m.store.Current().ConfigScope), "rejected", reason); publishErr != nil {
			return fmt.Errorf("reject config: %v; publish rejection status: %w", err, publishErr)
		}
		return err
	}
	if err := m.publishStatus(ctx, candidate, "applied", ""); err != nil {
		return fmt.Errorf("publish applied status: %w", err)
	}
	m.logger.Info("config fabric policy applied", "event", candidate.eventID, "policy", candidate.policyName, "version", candidate.version, "author", candidate.author)
	return nil
}

func (m *Manager) validate(ev *nostr.Event) (candidate, error) {
	if ev == nil {
		return candidate{}, errors.New("event is required")
	}
	c := candidate{eventID: ev.ID.Hex(), author: ev.PubKey.Hex()}
	if ev.Kind != nostr.Kind(cascadia.NIP78_APP_DATA) {
		return c, fmt.Errorf("kind must be %d", cascadia.NIP78_APP_DATA)
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return c, fmt.Errorf("invalid event signature: %w", err)
	}
	if !contains(m.store.Current().ConfigTrustedAuthors, c.author) {
		return c, errors.New("author is not trusted")
	}

	var err error
	if c.dTag, err = exactlyOne(ev.Tags, "d"); err != nil {
		return c, err
	}
	serviceTag, err := exactlyOne(ev.Tags, "service")
	if err != nil {
		return c, err
	}
	if c.scope, err = exactlyOne(ev.Tags, "scope"); err != nil {
		return c, err
	}
	versionTag, err := exactlyOne(ev.Tags, "version")
	if err != nil {
		return c, err
	}
	if c.schema, err = exactlyOne(ev.Tags, "schema"); err != nil {
		return c, err
	}

	prefix := "service:" + serviceID + ":"
	if !strings.HasPrefix(c.dTag, prefix) {
		return c, errors.New("wrong target service d-tag")
	}
	c.policyName = strings.TrimPrefix(c.dTag, prefix)
	if !contains(policy.SupportedDesiredPolicies(), c.policyName) {
		return c, fmt.Errorf("unsupported policy %q", c.policyName)
	}
	if serviceTag != serviceID {
		return c, fmt.Errorf("service tag must be %q", serviceID)
	}
	if c.scope != m.store.Current().ConfigScope {
		return c, fmt.Errorf("scope %q does not target this instance", c.scope)
	}
	c.version, err = strconv.ParseInt(versionTag, 10, 64)
	if err != nil || c.version < 1 {
		return c, errors.New("version tag must be a positive integer")
	}
	expectedSchema := "cascadia.config." + c.policyName + ".v1"
	if c.schema != expectedSchema {
		return c, fmt.Errorf("schema must be %q", expectedSchema)
	}

	var body envelope
	dec := json.NewDecoder(strings.NewReader(ev.Content))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return c, fmt.Errorf("decode config envelope: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return c, err
	}
	if body.ServiceID != serviceID || body.Scope != c.scope || body.Version != c.version || body.Schema != c.schema {
		return c, errors.New("content envelope does not match event tags")
	}
	if len(bytes.TrimSpace(body.Policy)) == 0 || bytes.Equal(bytes.TrimSpace(body.Policy), []byte("null")) {
		return c, errors.New("policy object is required")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body.Policy, &object); err != nil || object == nil {
		return c, errors.New("policy must be a JSON object")
	}
	for name, ref := range body.SecretRefs {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(ref.Ref) == "" {
			return c, errors.New("secret reference names and refs must be non-empty")
		}
		if ref.Provider != "signet" && ref.Provider != "file" && ref.Provider != "service" {
			return c, fmt.Errorf("secret reference %q has invalid provider", name)
		}
	}
	c.policy = body.Policy
	return c, nil
}

func ensureEOF(dec *json.Decoder) error {
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode config envelope: %w", err)
	}
	return nil
}

func exactlyOne(tags nostr.Tags, name string) (string, error) {
	var value string
	count := 0
	for _, tag := range tags {
		if len(tag) > 0 && tag[0] == name {
			count++
			if len(tag) != 2 || tag[1] == "" {
				return "", fmt.Errorf("%s tag must contain exactly one non-empty value", name)
			}
			value = tag[1]
		}
	}
	if count != 1 {
		return "", fmt.Errorf("event must contain exactly one %s tag", name)
	}
	return value, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func safeReason(err error) string {
	if errors.Is(err, policy.ErrStaleVersion) {
		return "version does not advance accepted coordinate"
	}
	reason := strings.TrimSpace(err.Error())
	lower := strings.ToLower(reason)
	if strings.Contains(lower, "decode ") || strings.Contains(lower, "url") || strings.Contains(lower, "requires immutable") {
		return "policy validation failed"
	}
	if len(reason) > 240 {
		reason = reason[:240]
	}
	return reason
}

func rejectionCandidate(ev *nostr.Event, c candidate, defaultScope string) candidate {
	if c.policyName == "" {
		c.policyName = "unknown"
	}
	if c.scope == "" {
		c.scope = defaultScope
		if c.scope == "" {
			c.scope = "prod"
		}
	}
	if c.schema == "" {
		c.schema = "cascadia.config." + c.policyName + ".v1"
	}
	if c.version < 1 {
		c.version = 1
	}
	if c.eventID == "" || len(c.eventID) != 64 {
		c.eventID = strings.Repeat("0", 64)
	}
	if ev != nil && len(ev.ID.Hex()) == 64 {
		c.eventID = ev.ID.Hex()
	}
	return c
}

func (m *Manager) publishStatus(ctx context.Context, c candidate, status, reason string) error {
	if m.publisher == nil {
		return errors.New("bridge identity signer is not configured")
	}
	ev, err := m.statusEvent(c, status, reason)
	if err != nil {
		return err
	}
	return m.publisher.PublishEvent(ctx, ev)
}

func (m *Manager) statusEvent(c candidate, status, reason string) (*nostr.Event, error) {
	effectiveVersion, lastEventID := m.store.EffectiveConfig(c.policyName)
	payload := cascadia.CascadiaConfigStatusV1Payload{
		ServiceId: serviceID, Scope: c.scope, Version: int(c.version), PolicySchema: c.schema,
		ConfigEventId: c.eventID, Status: status, EffectiveVersion: int(effectiveVersion),
		LastAppliedEventId: lastEventID, Reason: reason,
	}
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	content, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: nostr.Kind(cascadia.CAS_CP_STATE), Tags: nostr.Tags{
		{"d", "config-status:" + serviceID + ":" + c.policyName + ":" + c.scope},
		{"domain", "config-status"}, {"schema", statusSchema}, {"status", status},
		{"service", serviceID}, {"scope", c.scope}, {"version", strconv.FormatInt(c.version, 10)}, {"e", c.eventID},
	}, Content: string(content)}
	return ev, nil
}

func (m *Manager) PublishEnvSeedStatus(ctx context.Context, seed *policy.EnvSeedImport) error {
	if seed == nil {
		return nil
	}
	c := candidate{policyName: "env-seed", scope: m.store.Current().ConfigScope, schema: "cascadia.config.env-seed.v1", version: 1, eventID: seed.AuditID}
	if m.publisher == nil {
		return errors.New("bridge identity signer is not configured")
	}
	ev, err := m.statusEvent(c, "applied", "")
	if err != nil {
		return err
	}
	var content map[string]any
	if err := json.Unmarshal([]byte(ev.Content), &content); err != nil {
		return err
	}
	content["source"] = "env-seed"
	content["authorized_by"] = seed.AuthorizedBy
	content["considered_variables"] = seed.ConsideredVariables
	b, err := json.Marshal(content)
	if err != nil {
		return err
	}
	ev.Content = string(b)
	ev.Tags = append(ev.Tags, nostr.Tag{"source", "env-seed"})
	if err := m.publisher.PublishEvent(ctx, ev); err != nil {
		return err
	}
	if err := m.store.MarkEnvSeedStatusPublished(); err != nil {
		return fmt.Errorf("record seed status publication: %w", err)
	}
	m.logger.Info("authorized environment policy seed imported", "audit_id", seed.AuditID, "authorized_by", seed.AuthorizedBy, "considered_variables", seed.ConsideredVariables)
	return nil
}

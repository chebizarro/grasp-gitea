// Package policy provides the durable, live-reloadable bridge policy projection.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sharegap/grasp-gitea/internal/config"
)

const SchemaVersion = 1

type AccessPolicy struct {
	PubkeyAllowlist []string `json:"pubkey_allowlist"`
}

type CIPolicy struct {
	Enabled      bool     `json:"enabled"`
	TriggerRepos []string `json:"trigger_repos"`
}

type ProvisionPolicy struct {
	RateLimitPerHour int `json:"rate_limit_per_hour"`
}

type RelayPolicy struct {
	URLs          []string `json:"urls"`
	HookRelayURL  string   `json:"hook_relay_url"`
	GraspRelayURL string   `json:"grasp_relay_url"`
}

type ProfileSyncPolicy struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"`
	Workers  int    `json:"workers"`
}

type FullProxyPolicy struct {
	Enabled bool `json:"enabled"`
}

type EmbeddedRelayPolicy struct {
	Enabled bool `json:"enabled"`
}

type HiveCIPolicy struct {
	NostrRelays       []string `json:"nostr_relays"`
	CashuMintURL      string   `json:"cashu_mint_url"`
	BlossomURL        string   `json:"blossom_url"`
	JobTimeoutMinutes int      `json:"job_timeout_minutes"`
	CloneURLTemplate  string   `json:"clone_url_template"`
}

// Document is the complete persisted mutable-policy projection.
type Document struct {
	SchemaVersion int                 `json:"schema_version"`
	Access        AccessPolicy        `json:"access"`
	CI            CIPolicy            `json:"ci"`
	Provision     ProvisionPolicy     `json:"provision"`
	Relays        RelayPolicy         `json:"relays"`
	ProfileSync   ProfileSyncPolicy   `json:"profile_sync"`
	FullProxy     FullProxyPolicy     `json:"full_proxy"`
	EmbeddedRelay EmbeddedRelayPolicy `json:"embedded_relay"`
	HiveCI        HiveCIPolicy        `json:"hive_ci"`
}

// Snapshot contains immutable policy values consulted by concurrent consumers.
type Snapshot struct {
	PubkeyAllowlist        map[string]struct{}
	CITriggerRepos         []string
	CIEnabled              bool
	ProvisionRateLimit     int
	RelayURLs              []string
	HookRelayURL           string
	GraspRelayURL          string
	ProfileSyncEnabled     bool
	ProfileSyncInterval    time.Duration
	ProfileSyncWorkers     int
	FullProxyEnabled       bool
	EmbeddedRelay          bool
	HiveCINostrRelays      []string
	HiveCICashuMintURL     string
	HiveCIBlossomURL       string
	HiveCIJobTimeout       time.Duration
	HiveCICloneURLTemplate string
}

// Store owns persistence and atomically publishes validated snapshots.
type Store struct {
	current atomic.Pointer[Snapshot]
	mu      sync.Mutex
	path    string
	boot    config.Config
	changed chan struct{}
}

// New constructs an in-memory store for tests and compatibility callers.
func New(cfg config.Config) *Store {
	s := &Store{boot: cfg, changed: make(chan struct{})}
	s.publish(seedDocument(cfg))
	return s
}

// Open loads an existing projection, or atomically seeds it from legacy env-derived cfg.
// Existing persisted policy always wins over cfg.
func Open(path string, cfg config.Config) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("policy config path is required")
	}
	s := &Store{path: path, boot: cfg, changed: make(chan struct{})}
	doc, err := loadDocument(path)
	if errors.Is(err, os.ErrNotExist) {
		doc = seedDocument(cfg)
		if err := s.validate(doc); err != nil {
			return nil, fmt.Errorf("validate environment policy seed: %w", err)
		}
		if err := writeAtomic(path, doc); err != nil {
			return nil, fmt.Errorf("persist environment policy seed: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	if err := s.validate(doc); err != nil {
		return nil, fmt.Errorf("validate persisted policy: %w", err)
	}
	s.publish(doc)
	return s, nil
}

func seedDocument(cfg config.Config) Document {
	allowlist := make([]string, 0, len(cfg.PubkeyAllowlist))
	for pubkey := range cfg.PubkeyAllowlist {
		allowlist = append(allowlist, pubkey)
	}
	hiveRelays := append([]string(nil), cfg.HiveCINostrRelays...)
	if len(hiveRelays) == 0 {
		hiveRelays = append(hiveRelays, cfg.RelayURLs...)
	}
	jobMinutes := cfg.HiveCIJobTimeoutMinutes
	if jobMinutes <= 0 {
		jobMinutes = int(cfg.HiveCIRunTimeout / time.Minute)
		if jobMinutes <= 0 {
			jobMinutes = 15
		}
	}
	return Document{
		SchemaVersion: SchemaVersion,
		Access:        AccessPolicy{PubkeyAllowlist: allowlist},
		CI:            CIPolicy{Enabled: cfg.CIEnabled, TriggerRepos: append([]string(nil), cfg.CITriggerRepos...)},
		Provision:     ProvisionPolicy{RateLimitPerHour: cfg.ProvisionRateLimit},
		Relays:        RelayPolicy{URLs: append([]string(nil), cfg.RelayURLs...), HookRelayURL: cfg.HookRelayURL, GraspRelayURL: cfg.GraspRelayURL},
		ProfileSync:   ProfileSyncPolicy{Enabled: cfg.ProfileSyncEnabled, Interval: cfg.ProfileSyncInterval.String(), Workers: cfg.ProfileSyncWorkers},
		FullProxy:     FullProxyPolicy{Enabled: cfg.FullProxyEnabled},
		EmbeddedRelay: EmbeddedRelayPolicy{Enabled: cfg.EmbeddedRelay},
		HiveCI:        HiveCIPolicy{NostrRelays: hiveRelays, CashuMintURL: cfg.HiveCICashuMintURL, BlossomURL: cfg.HiveCIBlossomURL, JobTimeoutMinutes: jobMinutes, CloneURLTemplate: cfg.HiveCICloneURLTemplate},
	}
}

func loadDocument(path string) (Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return Document{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode policy %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Document{}, fmt.Errorf("decode policy %s: multiple JSON values", path)
	}
	return doc, nil
}

func (s *Store) validate(doc Document) error {
	if doc.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if doc.Provision.RateLimitPerHour < 0 {
		return errors.New("provision.rate_limit_per_hour must be non-negative")
	}
	for _, relayURL := range append(append([]string{}, doc.Relays.URLs...), doc.HiveCI.NostrRelays...) {
		if err := validateURL(relayURL, "ws", "wss"); err != nil {
			return err
		}
	}
	for _, relayURL := range []string{doc.Relays.HookRelayURL, doc.Relays.GraspRelayURL} {
		if relayURL != "" {
			if err := validateURL(relayURL, "ws", "wss"); err != nil {
				return err
			}
		}
	}
	for name, raw := range map[string]string{"hive_ci.cashu_mint_url": doc.HiveCI.CashuMintURL, "hive_ci.blossom_url": doc.HiveCI.BlossomURL} {
		if raw != "" {
			if err := validateURL(raw, "https"); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if doc.HiveCI.CloneURLTemplate != "" {
		if err := validateURL(doc.HiveCI.CloneURLTemplate, "http", "https"); err != nil {
			return fmt.Errorf("hive_ci.clone_url_template: %w", err)
		}
	}
	interval, err := time.ParseDuration(doc.ProfileSync.Interval)
	if err != nil || interval < time.Minute || interval > 24*time.Hour {
		return errors.New("profile_sync.interval must be between 1m and 24h")
	}
	if doc.ProfileSync.Workers < 1 || doc.ProfileSync.Workers > 32 {
		return errors.New("profile_sync.workers must be between 1 and 32")
	}
	if doc.HiveCI.JobTimeoutMinutes < 1 || doc.HiveCI.JobTimeoutMinutes > 60 {
		return errors.New("hive_ci.job_timeout_minutes must be between 1 and 60")
	}
	if len(doc.Relays.URLs) == 0 && !doc.EmbeddedRelay.Enabled {
		return errors.New("relays.urls is required unless embedded_relay.enabled is true")
	}
	if s.boot.LoomEnabled && len(s.boot.LoomRelayURLs) == 0 && len(doc.Relays.URLs) == 0 {
		return errors.New("relays.urls is required for Loom because the embedded relay rejects Loom kinds")
	}
	if (s.boot.HiveCIEnabled || (s.boot.LoomEnabled && s.boot.LoomDispatchMode != "local")) && len(doc.CI.TriggerRepos) == 0 {
		return errors.New("ci.trigger_repos is required for enabled CI execution")
	}
	if s.boot.HiveCIEnabled && len(doc.HiveCI.NostrRelays) == 0 {
		return errors.New("hive_ci.nostr_relays is required when Hive-CI is enabled")
	}
	if doc.ProfileSync.Enabled && s.boot.GiteaAdminUser == "" {
		return errors.New("profile_sync.enabled requires immutable GITEA_ADMIN_USER")
	}
	if s.boot.BridgeTokensEnabled && !doc.FullProxy.Enabled {
		return errors.New("full_proxy.enabled is required while bridge tokens are enabled")
	}
	if doc.FullProxy.Enabled && (s.boot.AuthEnabled || s.boot.Production()) && s.boot.EdgeSharedSecret == "" {
		return errors.New("full_proxy.enabled requires immutable GRASP_EDGE_SHARED_SECRET")
	}
	for _, repo := range doc.CI.TriggerRepos {
		repo = strings.TrimSpace(repo)
		if repo == "" || (repo != "*" && !strings.Contains(repo, "/")) {
			return fmt.Errorf("invalid ci.trigger_repos entry %q", repo)
		}
	}
	return nil
}

func validateURL(raw string, schemes ...string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid URL %q", raw)
	}
	for _, scheme := range schemes {
		if strings.EqualFold(u.Scheme, scheme) {
			return nil
		}
	}
	return fmt.Errorf("URL %q must use %s", raw, strings.Join(schemes, " or "))
}

func writeAtomic(path string, doc Document) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Store atomically replaces the in-memory snapshot from cfg. Persistent stores
// must use Update or Reload so durability always precedes activation.
func (s *Store) Store(cfg config.Config) { s.publish(seedDocument(cfg)) }

func (s *Store) publish(doc Document) {
	interval, _ := time.ParseDuration(doc.ProfileSync.Interval)
	allowlist := make(map[string]struct{}, len(doc.Access.PubkeyAllowlist))
	for _, pubkey := range doc.Access.PubkeyAllowlist {
		allowlist[strings.TrimSpace(pubkey)] = struct{}{}
	}
	s.current.Store(&Snapshot{
		PubkeyAllowlist: allowlist, CITriggerRepos: append([]string(nil), doc.CI.TriggerRepos...), CIEnabled: doc.CI.Enabled,
		ProvisionRateLimit: doc.Provision.RateLimitPerHour, RelayURLs: append([]string(nil), doc.Relays.URLs...), HookRelayURL: doc.Relays.HookRelayURL, GraspRelayURL: doc.Relays.GraspRelayURL,
		ProfileSyncEnabled: doc.ProfileSync.Enabled, ProfileSyncInterval: interval, ProfileSyncWorkers: doc.ProfileSync.Workers,
		FullProxyEnabled: doc.FullProxy.Enabled, EmbeddedRelay: doc.EmbeddedRelay.Enabled,
		HiveCINostrRelays: append([]string(nil), doc.HiveCI.NostrRelays...), HiveCICashuMintURL: doc.HiveCI.CashuMintURL, HiveCIBlossomURL: doc.HiveCI.BlossomURL,
		HiveCIJobTimeout: time.Duration(doc.HiveCI.JobTimeoutMinutes) * time.Minute, HiveCICloneURLTemplate: doc.HiveCI.CloneURLTemplate,
	})
}

func (s *Store) Current() *Snapshot {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Changes returns a channel closed on the next successful publish.
func (s *Store) Changes() <-chan struct{} {
	if s == nil {
		ch := make(chan struct{})
		return ch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

func (s *Store) notifyLocked() { close(s.changed); s.changed = make(chan struct{}) }

// Reload validates the persisted projection and atomically hot-applies it.
func (s *Store) Reload() error {
	if s == nil || s.path == "" {
		return errors.New("persistent policy store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := loadDocument(s.path)
	if err != nil {
		return err
	}
	if err := s.validate(doc); err != nil {
		return err
	}
	s.publish(doc)
	s.notifyLocked()
	return nil
}

// Document returns a defensive copy of the effective projection.
func (s *Store) Document() Document { return documentFromSnapshot(s.Current()) }

func documentFromSnapshot(v *Snapshot) Document {
	if v == nil {
		return Document{SchemaVersion: SchemaVersion}
	}
	allowlist := make([]string, 0, len(v.PubkeyAllowlist))
	for key := range v.PubkeyAllowlist {
		allowlist = append(allowlist, key)
	}
	return Document{SchemaVersion: SchemaVersion, Access: AccessPolicy{allowlist}, CI: CIPolicy{v.CIEnabled, append([]string(nil), v.CITriggerRepos...)}, Provision: ProvisionPolicy{v.ProvisionRateLimit}, Relays: RelayPolicy{append([]string(nil), v.RelayURLs...), v.HookRelayURL, v.GraspRelayURL}, ProfileSync: ProfileSyncPolicy{v.ProfileSyncEnabled, v.ProfileSyncInterval.String(), v.ProfileSyncWorkers}, FullProxy: FullProxyPolicy{v.FullProxyEnabled}, EmbeddedRelay: EmbeddedRelayPolicy{v.EmbeddedRelay}, HiveCI: HiveCIPolicy{append([]string(nil), v.HiveCINostrRelays...), v.HiveCICashuMintURL, v.HiveCIBlossomURL, int(v.HiveCIJobTimeout / time.Minute), v.HiveCICloneURLTemplate}}
}

// Group returns one named policy group.
func (s *Store) Group(name string) (any, bool) {
	d := s.Document()
	switch name {
	case "access":
		return d.Access, true
	case "ci":
		return d.CI, true
	case "provision":
		return d.Provision, true
	case "relays":
		return d.Relays, true
	case "profile_sync":
		return d.ProfileSync, true
	case "full_proxy":
		return d.FullProxy, true
	case "embedded_relay":
		return d.EmbeddedRelay, true
	case "hive_ci":
		return d.HiveCI, true
	}
	return nil, false
}

// UpdateGroup strictly decodes, validates, atomically persists, then publishes one group.
func (s *Store) UpdateGroup(name string, raw []byte) error {
	if s == nil || s.path == "" {
		return errors.New("persistent policy store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := documentFromSnapshot(s.Current())
	decode := func(dst any) error {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			return err
		}
		if dec.Decode(&struct{}{}) == nil {
			return errors.New("multiple JSON values")
		}
		return nil
	}
	var err error
	switch name {
	case "access":
		err = decode(&doc.Access)
	case "ci":
		err = decode(&doc.CI)
	case "provision":
		err = decode(&doc.Provision)
	case "relays":
		err = decode(&doc.Relays)
	case "profile_sync":
		err = decode(&doc.ProfileSync)
	case "full_proxy":
		err = decode(&doc.FullProxy)
	case "embedded_relay":
		err = decode(&doc.EmbeddedRelay)
	case "hive_ci":
		err = decode(&doc.HiveCI)
	default:
		return fmt.Errorf("unknown policy group %q", name)
	}
	if err != nil {
		return fmt.Errorf("decode %s policy: %w", name, err)
	}
	if err := s.validate(doc); err != nil {
		return err
	}
	if err := writeAtomic(s.path, doc); err != nil {
		return err
	}
	s.publish(doc)
	s.notifyLocked()
	return nil
}

// ApplyTo overlays mutable policy onto startup config after persisted load.
func (s *Store) ApplyTo(cfg *config.Config) {
	if cfg == nil {
		return
	}
	v := s.Current()
	if v == nil {
		return
	}
	cfg.PubkeyAllowlist = v.PubkeyAllowlist
	cfg.CITriggerRepos = append([]string(nil), v.CITriggerRepos...)
	cfg.CIEnabled = v.CIEnabled
	cfg.ProvisionRateLimit = v.ProvisionRateLimit
	cfg.RelayURLs = append([]string(nil), v.RelayURLs...)
	cfg.HookRelayURL = v.HookRelayURL
	cfg.GraspRelayURL = v.GraspRelayURL
	cfg.ProfileSyncEnabled = v.ProfileSyncEnabled
	cfg.ProfileSyncInterval = v.ProfileSyncInterval
	cfg.ProfileSyncWorkers = v.ProfileSyncWorkers
	cfg.FullProxyEnabled = v.FullProxyEnabled
	cfg.EmbeddedRelay = v.EmbeddedRelay
}

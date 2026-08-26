// Package policy provides the durable, live-reloadable bridge policy projection.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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

type AcceptedConfig struct {
	Author    string    `json:"author"`
	Scope     string    `json:"scope"`
	DTag      string    `json:"d_tag"`
	Schema    string    `json:"schema"`
	Version   int64     `json:"version"`
	EventID   string    `json:"event_id"`
	AppliedAt time.Time `json:"applied_at"`
}

type EnvSeedImport struct {
	AuditID             string    `json:"audit_id"`
	AuthorizedBy        string    `json:"authorized_by"`
	ConsideredVariables []string  `json:"considered_variables"`
	ImportedAt          time.Time `json:"imported_at"`
	StatusPublished     bool      `json:"status_published"`
}

type ConfigFabricSettings struct {
	TrustedAuthors []string `json:"trusted_authors"`
	Scope          string   `json:"scope"`
}

type ConfigFabricPolicy struct {
	TrustedAuthors []string                  `json:"trusted_authors"`
	Scope          string                    `json:"scope"`
	Accepted       map[string]AcceptedConfig `json:"accepted"`
	EnvSeed        *EnvSeedImport            `json:"env_seed_import,omitempty"`
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
	ConfigFabric  ConfigFabricPolicy  `json:"config_fabric"`
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
	ConfigTrustedAuthors   []string
	ConfigScope            string
	AcceptedConfig         map[string]AcceptedConfig
	EnvSeedImport          *EnvSeedImport
}

// Store owns persistence and atomically publishes validated snapshots.
type Store struct {
	current  atomic.Pointer[Snapshot]
	document atomic.Pointer[Document]
	mu       sync.Mutex
	path     string
	boot     config.Config
	changed  chan struct{}
	seeded   bool
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
		seed := newEnvSeedImport(doc)
		doc.ConfigFabric.EnvSeed = &seed
		if err := writeAtomic(path, doc); err != nil {
			return nil, fmt.Errorf("persist environment policy seed: %w", err)
		}
		s.seeded = true
	} else if err != nil {
		return nil, err
	} else if doc.ConfigFabric.Scope == "" {
		doc.ConfigFabric.Scope = cfg.ConfigScope
		if doc.ConfigFabric.Scope == "" {
			doc.ConfigFabric.Scope = "prod"
		}
		if doc.ConfigFabric.Accepted == nil {
			doc.ConfigFabric.Accepted = make(map[string]AcceptedConfig)
		}
		if err := writeAtomic(path, doc); err != nil {
			return nil, fmt.Errorf("persist config-fabric metadata migration: %w", err)
		}
	}
	if err := s.validate(doc); err != nil {
		return nil, fmt.Errorf("validate persisted policy: %w", err)
	}
	s.publish(doc)
	return s, nil
}

var envSeedVariables = []string{"PUBKEY_ALLOWLIST", "CI_ENABLED", "CI_TRIGGER_REPOS", "PROVISION_RATE_LIMIT", "RELAY_URLS", "HOOK_RELAY_URL", "GRASP_RELAY_URL", "PROFILE_SYNC_ENABLED", "PROFILE_SYNC_INTERVAL", "PROFILE_SYNC_WORKERS", "GITEA_FULL_PROXY_ENABLED", "EMBEDDED_RELAY", "NOSTR_RELAYS", "CASHU_MINT_URL", "BLOSSOM_URL", "JOB_TIMEOUT_MINUTES", "HIVECI_CLONE_URL_TEMPLATE", "GRASP_CONFIG_TRUSTED_AUTHORS", "GRASP_CONFIG_SCOPE"}

func newEnvSeedImport(doc Document) EnvSeedImport {
	doc.ConfigFabric.EnvSeed = nil
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return EnvSeedImport{AuditID: fmt.Sprintf("%x", sum), AuthorizedBy: "local-bootstrap", ConsideredVariables: append([]string(nil), envSeedVariables...), ImportedAt: time.Now().UTC()}
}

func seedDocument(cfg config.Config) Document {
	if strings.TrimSpace(cfg.ConfigScope) == "" {
		cfg.ConfigScope = "prod"
	}
	allowlist := make([]string, 0, len(cfg.PubkeyAllowlist))
	for pubkey := range cfg.PubkeyAllowlist {
		allowlist = append(allowlist, pubkey)
	}
	sort.Strings(allowlist)
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
		ConfigFabric:  ConfigFabricPolicy{TrustedAuthors: append([]string(nil), cfg.ConfigTrustedAuthors...), Scope: cfg.ConfigScope, Accepted: make(map[string]AcceptedConfig)},
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
	if !validScope(doc.ConfigFabric.Scope) {
		return fmt.Errorf("config_fabric.scope %q is invalid", doc.ConfigFabric.Scope)
	}
	seenAuthors := make(map[string]struct{}, len(doc.ConfigFabric.TrustedAuthors))
	for _, author := range doc.ConfigFabric.TrustedAuthors {
		if !validHex32(author) || author != strings.ToLower(author) {
			return fmt.Errorf("config_fabric.trusted_authors contains invalid pubkey %q", author)
		}
		if _, exists := seenAuthors[author]; exists {
			return fmt.Errorf("config_fabric.trusted_authors contains duplicate pubkey %q", author)
		}
		seenAuthors[author] = struct{}{}
	}
	for coordinate, accepted := range doc.ConfigFabric.Accepted {
		policyName := strings.TrimPrefix(accepted.DTag, "service:grasp-bridge:")
		_, supported := supportedDesiredPolicies[policyName]
		wantCoordinate := accepted.Author + "|" + accepted.Scope + "|" + accepted.DTag
		if accepted.Version < 1 || !validHex32(accepted.EventID) || !validHex32(accepted.Author) || !validScope(accepted.Scope) || !supported || accepted.Schema != "cascadia.config."+policyName+".v1" || coordinate != wantCoordinate || accepted.AppliedAt.IsZero() {
			return fmt.Errorf("config_fabric.accepted[%q] is invalid", coordinate)
		}
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

func validHex32(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32
}

func validScope(scope string) bool {
	if scope == "prod" || scope == "staging" || scope == "fleet" {
		return true
	}
	if !strings.HasPrefix(scope, "host:") || len(scope) <= len("host:") {
		return false
	}
	for _, r := range strings.TrimPrefix(scope, "host:") {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
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
	docCopy := cloneDocument(doc)
	s.document.Store(&docCopy)
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
		ConfigTrustedAuthors: append([]string(nil), doc.ConfigFabric.TrustedAuthors...), ConfigScope: doc.ConfigFabric.Scope, AcceptedConfig: cloneAccepted(doc.ConfigFabric.Accepted), EnvSeedImport: cloneEnvSeed(doc.ConfigFabric.EnvSeed),
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

// Document returns a defensive copy of the effective projection and validation metadata.
func (s *Store) Document() Document {
	if s == nil || s.document.Load() == nil {
		return Document{SchemaVersion: SchemaVersion}
	}
	return cloneDocument(*s.document.Load())
}

func cloneDocument(doc Document) Document {
	b, _ := json.Marshal(doc)
	var out Document
	_ = json.Unmarshal(b, &out)
	return out
}

func cloneAccepted(in map[string]AcceptedConfig) map[string]AcceptedConfig {
	out := make(map[string]AcceptedConfig, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneEnvSeed(in *EnvSeedImport) *EnvSeedImport {
	if in == nil {
		return nil
	}
	out := *in
	out.ConsideredVariables = append([]string(nil), in.ConsideredVariables...)
	return &out
}

func (s *Store) SeedImport() (*EnvSeedImport, bool) {
	if s == nil {
		return nil, false
	}
	return cloneEnvSeed(s.Current().EnvSeedImport), s.seeded
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
	case "config_fabric":
		return ConfigFabricSettings{TrustedAuthors: append([]string(nil), d.ConfigFabric.TrustedAuthors...), Scope: d.ConfigFabric.Scope}, true
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
	doc := s.Document()
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
	case "config_fabric":
		var settings ConfigFabricSettings
		err = decode(&settings)
		if err == nil {
			doc.ConfigFabric.TrustedAuthors = settings.TrustedAuthors
			doc.ConfigFabric.Scope = settings.Scope
		}
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

var ErrStaleVersion = errors.New("config version does not advance accepted coordinate")

var supportedDesiredPolicies = map[string]string{
	"access":         "access",
	"ci":             "ci",
	"provision":      "provision",
	"relays":         "relays",
	"profile-sync":   "profile_sync",
	"full-proxy":     "full_proxy",
	"embedded-relay": "embedded_relay",
	"hive-ci":        "hive_ci",
}

func SupportedDesiredPolicies() []string {
	out := make([]string, 0, len(supportedDesiredPolicies))
	for name := range supportedDesiredPolicies {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type DesiredUpdate struct {
	Author     string
	Scope      string
	DTag       string
	PolicyName string
	Schema     string
	Version    int64
	EventID    string
	AppliedAt  time.Time
}

// ApplyDesired validates a policy group, atomically persists it with its accepted
// event coordinate, and only then publishes the hot snapshot.
func (s *Store) ApplyDesired(update DesiredUpdate, raw []byte) error {
	if s == nil || s.path == "" {
		return errors.New("persistent policy store is not configured")
	}
	group, ok := supportedDesiredPolicies[update.PolicyName]
	if !ok {
		return fmt.Errorf("unsupported desired policy %q", update.PolicyName)
	}
	if update.Version < 1 {
		return errors.New("version must be positive")
	}
	if update.EventID == "" {
		return errors.New("event id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	doc := s.Document()
	coordinate := update.Author + "|" + update.Scope + "|" + update.DTag
	if prior, exists := doc.ConfigFabric.Accepted[coordinate]; exists && update.Version <= prior.Version {
		return fmt.Errorf("%w: got %d, accepted %d", ErrStaleVersion, update.Version, prior.Version)
	}
	if err := decodeDesiredGroup(&doc, group, raw); err != nil {
		return err
	}
	if doc.ConfigFabric.Accepted == nil {
		doc.ConfigFabric.Accepted = make(map[string]AcceptedConfig)
	}
	appliedAt := update.AppliedAt.UTC()
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}
	doc.ConfigFabric.Accepted[coordinate] = AcceptedConfig{
		Author: update.Author, Scope: update.Scope, DTag: update.DTag, Schema: update.Schema,
		Version: update.Version, EventID: update.EventID, AppliedAt: appliedAt,
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

func decodeDesiredGroup(doc *Document, group string, raw []byte) error {
	decode := func(dst any) error {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			return err
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("multiple JSON values")
		}
		return nil
	}
	var err error
	switch group {
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
		return fmt.Errorf("unknown policy group %q", group)
	}
	if err != nil {
		return fmt.Errorf("decode %s policy: %w", group, err)
	}
	return nil
}

func (s *Store) EffectiveConfig(policyName string) (int64, string) {
	if s == nil {
		return 1, ""
	}
	var best AcceptedConfig
	for _, accepted := range s.Current().AcceptedConfig {
		if accepted.DTag == "service:grasp-bridge:"+policyName && accepted.AppliedAt.After(best.AppliedAt) {
			best = accepted
		}
	}
	if best.Version == 0 {
		if seed := s.Current().EnvSeedImport; seed != nil {
			return 1, seed.AuditID
		}
		return 1, ""
	}
	return best.Version, best.EventID
}

// MarkEnvSeedStatusPublished durably records successful publication so a relay outage retries on the next boot.
func (s *Store) MarkEnvSeedStatusPublished() error {
	if s == nil || s.path == "" {
		return errors.New("persistent policy store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := s.Document()
	if doc.ConfigFabric.EnvSeed == nil || doc.ConfigFabric.EnvSeed.StatusPublished {
		return nil
	}
	doc.ConfigFabric.EnvSeed.StatusPublished = true
	if err := writeAtomic(s.path, doc); err != nil {
		return err
	}
	s.publish(doc)
	s.notifyLocked()
	return nil
}

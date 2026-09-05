package provisioner

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/grasp"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/nostrprofile"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type tenantPlacementCoordinator interface {
	WithPlacement(context.Context, string, func(context.Context, store.ManagedTenant) error) (bool, error)
}

var errTenantPlacementDeclined = errors.New("tenant placement declined")

type Service struct {
	cfg               config.Config
	store             *store.SQLiteStore
	authStore         store.AuthStore
	tenantPlacement   tenantPlacementCoordinator
	gitea             *gitea.Client
	logger            *slog.Logger
	installer         *hooks.Installer
	resolver          *nip05resolve.Resolver
	policy            *policy.Store
	verifyAffiliation func(context.Context, string, []string) nip05resolve.AffiliationVerification

	// repoMu serializes provisioning per (npub, repoID) to prevent concurrent
	// races when multiple events for the same repo arrive simultaneously.
	repoMu    sync.Mutex
	repoLocks map[string]*sync.Mutex
}

// SetPolicyStore makes repository admission consult live policy snapshots.
func (s *Service) SetPolicyStore(store *policy.Store) {
	s.policy = store
}

type Result struct {
	Npub   string `json:"npub"`
	RepoID string `json:"repo_id"`
	Owner  string `json:"owner"`
	Repo   string `json:"repo"`
	Event  string `json:"event"`
}

func New(cfg config.Config, st *store.SQLiteStore, authStore store.AuthStore, tenantPlacement tenantPlacementCoordinator, g *gitea.Client, installer *hooks.Installer, resolver *nip05resolve.Resolver, logger *slog.Logger) *Service {
	if authStore == nil {
		authStore = st
	}
	return &Service{
		cfg: cfg, store: st, authStore: authStore, tenantPlacement: tenantPlacement, gitea: g,
		installer: installer, resolver: resolver, logger: logger,
		verifyAffiliation: nip05resolve.VerifyAffiliationFresh,
		repoLocks:         make(map[string]*sync.Mutex),
	}
}

// lockRepo serializes namespace provisioning for one Nostr owner. This avoids
// two repositories racing to create or claim the same organization.
func (s *Service) lockRepo(npub, _ string) *sync.Mutex {
	key := npub
	s.repoMu.Lock()
	mu, ok := s.repoLocks[key]
	if !ok {
		mu = &sync.Mutex{}
		s.repoLocks[key] = mu
	}
	s.repoMu.Unlock()
	mu.Lock()
	return mu
}

// linkedOwner returns the organization explicitly linked to this Nostr
// identity by an existing repository mapping.
func (s *Service) linkedOwner(ctx context.Context, npub, pubkey string) (string, bool, error) {
	mappings, err := s.store.ListMappings(ctx)
	if err != nil {
		return "", false, fmt.Errorf("list ownership links: %w", err)
	}
	owner := ""
	for _, m := range mappings {
		if m.Npub != npub || m.TenantHost != "" {
			continue
		}
		if m.Pubkey != pubkey {
			return "", false, fmt.Errorf("stored identity mismatch for %s", npub)
		}
		if m.Owner == "" {
			return "", false, fmt.Errorf("stored ownership link for %s has no organization", npub)
		}
		if owner != "" && owner != m.Owner {
			return "", false, fmt.Errorf("conflicting organization links for %s: %s and %s", npub, owner, m.Owner)
		}
		owner = m.Owner
	}
	if owner != "" {
		for _, m := range mappings {
			if strings.EqualFold(m.Owner, owner) && m.TenantHost == "" && m.Pubkey != pubkey {
				return "", false, fmt.Errorf("organization %s is linked to multiple Nostr identities", owner)
			}
		}
	}
	return owner, owner != "", nil
}

func (s *Service) HandleAnnouncementEvent(ctx context.Context, ev *nostr.Event, relayURL string) error {
	metrics.IncAnnouncementReceived()
	if ev == nil {
		metrics.IncAnnouncementRejected()
		return errors.New("nil event")
	}
	if ev.Kind != relay.KindRepositoryAnnouncement {
		return nil
	}

	processed, err := s.store.EventProcessed(ctx, ev.ID.Hex())
	if err != nil {
		metrics.IncAnnouncementRejected()
		return err
	}
	if processed {
		return nil
	}

	if ev.ID == (nostr.ID{}) || ev.PubKey == (nostr.PubKey{}) {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("invalid announcement: missing id/pubkey")
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("announcement cryptographic validation failed: %w", err)
	}

	npub := nip19.EncodeNpub(ev.PubKey)

	repoID := getTagValue(ev.Tags, "d")
	if repoID == "" {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("missing d tag for announcement %s", ev.ID)
	}

	cloneURL, ok := findCloneForService(ev.Tags, s.cfg.GraspPublicURL, s.cfg.ClonePrefix, npub, repoID)
	if !ok {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("announcement %s does not list this service in clone tags", ev.ID)
	}
	if !cloneMatchesRepoID(cloneURL, repoID) {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("announcement %s clone URL does not match repo id %s", ev.ID, repoID)
	}
	if !hasRelayForService(ev.Tags, s.serviceRelayURL()) {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("announcement %s does not list this service in relays tags", ev.ID)
	}

	if err := s.provisionFromAnnouncement(ctx, npub, ev.PubKey.Hex(), repoID, cloneURL, ev.ID.Hex(), relayURL, tenantPlacementIntent(ev.Tags)); err != nil {
		metrics.IncAnnouncementRejected()
		return err
	}

	// Cache the raw owner-signed announcement for later republishing (e.g. mirror sync).
	if cacheErr := s.CacheAnnouncementEvent(ctx, ev); cacheErr != nil {
		s.logger.Warn("failed to cache announcement event", "event", ev.ID.Hex(), "error", cacheErr)
	}

	if err := s.store.MarkEventProcessed(ctx, ev.ID.Hex(), ev.PubKey.Hex(), int(ev.Kind)); err != nil {
		metrics.IncAnnouncementRejected()
		return err
	}

	metrics.IncAnnouncementProvisioned()
	return nil
}

func (s *Service) ManualProvision(ctx context.Context, npub string, pubkey string, repoID string) (Result, error) {
	metrics.IncManualProvisionRequests()
	if strings.TrimSpace(pubkey) == "" {
		t, value, err := nip19.Decode(npub)
		if err != nil {
			metrics.IncManualProvisionFailures()
			return Result{}, fmt.Errorf("decode npub: %w", err)
		}
		if t != "npub" {
			metrics.IncManualProvisionFailures()
			return Result{}, fmt.Errorf("expected npub, got %s", t)
		}
		decoded, ok := value.(nostr.PubKey)
		if !ok {
			metrics.IncManualProvisionFailures()
			return Result{}, fmt.Errorf("invalid decoded npub value")
		}
		pubkey = decoded.Hex()
	}

	cloneURL := grasp.CanonicalCloneURL(s.cfg.GraspPublicURL, npub, repoID)
	if cloneURL == "" {
		cloneURL = fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, npub, repoID)
	}
	err := s.provisionFromAnnouncement(ctx, npub, pubkey, repoID, cloneURL, "manual", "manual", "")
	if err != nil {
		metrics.IncManualProvisionFailures()
		return Result{}, err
	}

	// Fetch final org name from the stored mapping.
	m, _ := s.store.GetMapping(ctx, npub, repoID)
	orgName := m.Owner
	if orgName == "" {
		orgName = npub
	}
	return Result{Npub: npub, RepoID: repoID, Owner: orgName, Repo: repoID, Event: "manual"}, nil
}

func (s *Service) provisionFromAnnouncement(ctx context.Context, npub string, pubkey string, repoID string, cloneURL string, sourceEvent string, sourceRelay string, placementIntent string) error {
	if err := s.validatePolicy(ctx, npub, pubkey); err != nil {
		return err
	}

	// Serialize all namespace provisioning for this Nostr owner.
	mu := s.lockRepo(npub, repoID)
	defer mu.Unlock()

	relayURLs := s.cfg.RelayURLs
	if snapshot := s.policy.Current(); snapshot != nil {
		relayURLs = snapshot.RelayURLs
	}
	if sourceRelay != "manual" && sourceRelay != "" {
		// Try the source relay first (it just delivered this event, likely has kind 0 too).
		relayURLs = append([]string{sourceRelay}, relayURLs...)
	}

	// A stored mapping is the explicit ownership link that permits an existing
	// Gitea namespace to be reused. Without one, creation is strict and any
	// pre-existing org/repo causes provisioning to fail closed.
	existing, err := s.store.GetMapping(ctx, npub, repoID)
	exactLinked := err == nil
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup ownership link: %w", err)
	}

	orgName, repoName, tenantHost := "", repoID, ""
	orgLinked, tenantPlaced := false, false
	collaboratorUser := ""
	var repo gitea.Repository
	repoCreated := false
	if exactLinked {
		if existing.Pubkey != pubkey || existing.Owner == "" || existing.RepoName == "" || existing.GiteaRepoID <= 0 {
			return fmt.Errorf("stored mapping %s/%s does not match announcing identity", npub, repoID)
		}
		orgName, repoName, tenantHost, orgLinked = existing.Owner, existing.RepoName, existing.TenantHost, true
		tenantPlaced = tenantHost != ""
		if tenantPlaced {
			if link, linkErr := s.authStore.GetIdentityLinkByPubkey(ctx, pubkey); linkErr == nil {
				collaboratorUser = link.GiteaUser
			} else if !errors.Is(linkErr, sql.ErrNoRows) {
				return fmt.Errorf("lookup tenant repository owner: %w", linkErr)
			}
		}
	} else if placementIntent != "" && s.tenantPlacement != nil {
		placed, placementErr := s.tenantPlacement.WithPlacement(ctx, placementIntent, func(lockedCtx context.Context, tenant store.ManagedTenant) error {
			user, authorized := s.authorizeTenantPlacement(lockedCtx, pubkey, tenant, relayURLs)
			if !authorized {
				return errTenantPlacementDeclined
			}
			orgName, repoName, tenantHost = tenant.OrgName, tenantRepoName(repoID, pubkey), tenant.Host
			orgLinked, tenantPlaced, collaboratorUser = true, true, user
			var createErr error
			repo, createErr = s.gitea.CreateRepo(lockedCtx, orgName, repoName)
			if createErr != nil {
				return fmt.Errorf("create tenant repo %s/%s: %w", orgName, repoName, createErr)
			}
			repoCreated = true
			return nil
		})
		if placementErr != nil && !errors.Is(placementErr, errTenantPlacementDeclined) {
			return placementErr
		}
		if !placed || errors.Is(placementErr, errTenantPlacementDeclined) {
			orgName, orgLinked, err = s.linkedOwner(ctx, npub, pubkey)
			if err != nil {
				return err
			}
		}
	} else {
		orgName, orgLinked, err = s.linkedOwner(ctx, npub, pubkey)
		if err != nil {
			return err
		}
	}
	if !orgLinked {
		// Resolve a stable domain-qualified NIP-05 name, falling back to a
		// collision-resistant hex prefix when no verified identifier exists.
		orgName = s.resolver.ResolveOrgName(ctx, pubkey, relayURLs)
	}

	s.logger.Info("resolved org ownership", "npub", npub, "org_name", orgName, "repo_name", repoName, "linked", orgLinked, "tenant_placed", tenantPlaced)

	// Preserve the original announced clone URL for traceability.
	// The actual Gitea clone URL uses the mapped physical owner and name.
	announcedCloneURL := cloneURL
	giteaCloneURL := fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, orgName, repoName)

	if orgLinked {
		if err := s.gitea.EnsureOrg(ctx, orgName); err != nil {
			return fmt.Errorf("ensure linked org %s: %w", orgName, err)
		}
	} else if err := s.gitea.CreateOrg(ctx, orgName); err != nil {
		return fmt.Errorf("create unlinked org %s: %w", orgName, err)
	}

	// A tenant org represents the domain, not one member; never overwrite its
	// managed profile with a repository owner's kind:0 metadata.
	if !tenantPlaced {
		if profile, err := nostrprofile.Fetch(ctx, pubkey, relayURLs); err != nil {
			s.logger.Debug("nostr profile fetch failed (non-fatal)", "pubkey", pubkey, "error", err)
		} else if profile != nil && !profile.IsEmpty() {
			if syncErr := s.gitea.SyncNostrProfile(ctx, "", orgName, *profile); syncErr != nil {
				s.logger.Warn("nostr profile sync partial failure (non-fatal)", "org", orgName, "error", syncErr)
			} else {
				s.logger.Info("synced nostr profile to gitea org", "org", orgName, "display_name", profile.DisplayName)
			}
		}
	}

	if exactLinked {
		repo, err = s.gitea.EnsureRepo(ctx, orgName, repoName)
		if err != nil {
			return fmt.Errorf("ensure linked repo %s/%s: %w", orgName, repoName, err)
		}
		if repo.ID != existing.GiteaRepoID {
			return fmt.Errorf("linked repo %s/%s has Gitea id %d, expected %d", orgName, repoName, repo.ID, existing.GiteaRepoID)
		}
	} else if !repoCreated {
		repo, err = s.gitea.CreateRepo(ctx, orgName, repoName)
		if err != nil {
			return fmt.Errorf("create unlinked repo %s/%s: %w", orgName, repoName, err)
		}
	}

	// Phase 1: Record mapping with hook_installed=false.
	// If the bridge crashes after this point, ReconcileHooks will
	// find the incomplete mapping on startup and re-install the hook.
	mapping := store.Mapping{
		Npub:              npub,
		RepoID:            repoID,
		Pubkey:            pubkey,
		Owner:             orgName,
		RepoName:          repoName,
		TenantHost:        tenantHost,
		GiteaRepoID:       repo.ID,
		CloneURL:          giteaCloneURL,
		AnnouncedCloneURL: announcedCloneURL,
		SourceEvent:       sourceEvent,
		HookInstalled:     false,
	}
	if err := s.store.UpsertMapping(ctx, mapping); err != nil {
		return fmt.Errorf("save mapping: %w", err)
	}
	if tenantPlaced {
		if collaboratorUser == "" {
			return fmt.Errorf("tenant repository owner has no linked Gitea user")
		}
		if err := s.gitea.AddOrUpdateCollaborator(ctx, orgName, repoName, collaboratorUser, "write"); err != nil {
			return fmt.Errorf("grant tenant repository owner collaborator access: %w", err)
		}
	}

	// Phase 2: Install the pre-receive hook, then mark as complete.
	if s.installer != nil {
		if err := s.installer.InstallAt(orgName, repoName, npub, repoID); err != nil {
			return fmt.Errorf("install pre-receive hook: %w", err)
		}
	}

	if err := s.store.SetHookInstalled(ctx, npub, repoID, true); err != nil {
		return fmt.Errorf("mark hook installed: %w", err)
	}

	s.logger.Info("provisioned repository", "npub", npub, "org_name", orgName, "repo_id", repoID, "relay", sourceRelay, "event", sourceEvent)
	return nil
}

// CacheAnnouncementEvent persists the raw owner-signed announcement event
// so the publisher can republish it later (e.g. after mirror syncs).
func (s *Service) CacheAnnouncementEvent(ctx context.Context, ev *nostr.Event) error {
	if ev == nil || ev.Kind != relay.KindRepositoryAnnouncement {
		return nil
	}
	npub := nip19.EncodeNpub(ev.PubKey)
	repoID := getTagValue(ev.Tags, "d")
	if repoID == "" {
		return nil
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal announcement event: %w", err)
	}
	return s.store.SetAnnouncementEvent(ctx, npub, repoID, string(raw), ev.ID.Hex())
}

// ReconcileHooks re-installs hooks for any mappings where provisioning
// was interrupted before hook installation completed. Call on startup.
func (s *Service) ReconcileHooks(ctx context.Context) error {
	pending, err := s.store.ListUnhookedMappings(ctx)
	if err != nil {
		return fmt.Errorf("list unhooked mappings: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}

	s.logger.Info("reconciling incomplete provisioning", "count", len(pending))

	var reconcileErrors []error
	for _, m := range pending {
		// The exact mapping, including immutable repository ID below, is the
		// durable ownership link. Tenant placement intentionally permits one
		// pubkey to have repositories in more than one Gitea organization.
		if err := s.gitea.EnsureOrg(ctx, m.Owner); err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: ensure org: %w", m.Owner, m.RepoID, err))
			continue
		}
		if repo, err := s.gitea.EnsureRepo(ctx, m.Owner, m.RepoName); err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: ensure repo: %w", m.Owner, m.RepoName, err))
			continue
		} else if repo.ID != m.GiteaRepoID {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: Gitea id %d, expected %d", m.Owner, m.RepoName, repo.ID, m.GiteaRepoID))
			continue
		}
		if m.TenantHost != "" {
			link, err := s.authStore.GetIdentityLinkByPubkey(ctx, m.Pubkey)
			if err != nil || link.GiteaUserID <= 0 || link.GiteaUser == "" {
				if err == nil {
					err = errors.New("identity link has no Gitea user")
				}
				reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: lookup owner collaborator: %w", m.Owner, m.RepoName, err))
				continue
			}
			if err := s.gitea.AddOrUpdateCollaborator(ctx, m.Owner, m.RepoName, link.GiteaUser, "write"); err != nil {
				reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: restore owner collaborator: %w", m.Owner, m.RepoName, err))
				continue
			}
		}
		if s.installer != nil {
			if err := s.installer.InstallAt(m.Owner, m.RepoName, m.Npub, m.RepoID); err != nil {
				reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: install hook: %w", m.Owner, m.RepoID, err))
				continue
			}
		}
		if err := s.store.SetHookInstalled(ctx, m.Npub, m.RepoID, true); err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile %s/%s: mark installed: %w", m.Owner, m.RepoID, err))
			continue
		}
		s.logger.Info("reconciled hook for repository", "owner", m.Owner, "repo_id", m.RepoID)
	}

	return errors.Join(reconcileErrors...)
}

// EnsureUploadPackCapabilities migrates every mapped repository to the
// required GRASP-01 upload-pack capability configuration. Call on startup.
func (s *Service) EnsureUploadPackCapabilities(ctx context.Context) error {
	mappings, err := s.store.ListMappings(ctx)
	if err != nil {
		return fmt.Errorf("list mappings: %w", err)
	}
	var errs []error
	for _, m := range mappings {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.installer.ConfigureUploadPack(m.Owner, m.RepoName); err != nil {
			errs = append(errs, fmt.Errorf("upload-pack config %s/%s: %w", m.Owner, m.RepoID, err))
			continue
		}
	}
	return errors.Join(errs...)
}

func (s *Service) validatePolicy(ctx context.Context, npub string, pubkey string) error {
	allowlist := s.cfg.PubkeyAllowlist
	if snapshot := s.policy.Current(); snapshot != nil {
		allowlist = snapshot.PubkeyAllowlist
	}
	if len(allowlist) > 0 {
		if _, ok := allowlist[pubkey]; !ok {
			if _, ok := allowlist[npub]; !ok {
				return fmt.Errorf("pubkey %s not allowlisted", pubkey)
			}
		}
	}

	rateLimit := s.cfg.ProvisionRateLimit
	if snapshot := s.policy.Current(); snapshot != nil {
		rateLimit = snapshot.ProvisionRateLimit
	}
	if rateLimit > 0 {
		count, err := s.store.ProvisionCountSince(ctx, pubkey, time.Now().Add(-1*time.Hour))
		if err != nil {
			return err
		}
		if count >= rateLimit {
			return fmt.Errorf("rate limit exceeded for pubkey %s", pubkey)
		}
	}

	return nil
}

func tenantPlacementIntent(tags nostr.Tags) string {
	intent := ""
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != "tenant" {
			continue
		}
		if len(tag) != 2 || intent != "" {
			return ""
		}
		host, err := nip05resolve.CanonicalizeHost(tag[1])
		if err != nil {
			return ""
		}
		intent = host
	}
	return intent
}

func tenantRepoName(repoID, pubkey string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(pubkey)))
	return repoID + "-" + hex.EncodeToString(sum[:10])
}

// authorizeTenantPlacement performs member authorization while the tenant
// coordinator holds the shared tenant lock. Every failed or ambiguous check
// declines placement into the tenant namespace.
func (s *Service) authorizeTenantPlacement(ctx context.Context, pubkey string, tenant store.ManagedTenant, relayURLs []string) (string, bool) {
	verify := s.verifyAffiliation
	if verify == nil {
		verify = nip05resolve.VerifyAffiliationFresh
	}
	verification := verify(ctx, pubkey, relayURLs)
	if !verification.Verified() || verification.Host != tenant.Host {
		return "", false
	}
	if err := s.authStore.UpsertDomainAffiliation(ctx, store.DomainAffiliation{
		CanonicalIdentifier: verification.CanonicalIdentifier,
		LocalPart:           verification.LocalPart,
		Host:                verification.Host,
		Pubkey:              strings.ToLower(pubkey),
		VerifiedAt:          verification.VerifiedAt,
		CheckedAt:           verification.VerifiedAt,
		Status:              store.DomainAffiliationVerified,
	}); err != nil {
		return "", false
	}
	link, err := s.authStore.GetIdentityLinkByPubkey(ctx, pubkey)
	if err != nil || link.GiteaUserID <= 0 || link.GiteaUser == "" {
		return "", false
	}
	if _, err := s.authStore.GetTenantSCIMToken(ctx, tenant.Host); err == nil {
		authorized, listErr := s.authStore.ListSCIMAuthorizedUsers(ctx, tenant.Host)
		if listErr != nil {
			return "", false
		}
		allowed := false
		for _, user := range authorized {
			if strings.EqualFold(user.Pubkey, pubkey) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", false
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	return link.GiteaUser, true
}

func getTagValue(tags nostr.Tags, key string) string {
	v := tags.Find(key)
	if v == nil || len(v) < 2 {
		return ""
	}
	return v[1]
}

// serviceRelayURL returns the relay URL announcements must advertise: the
// canonical GRASP relay origin when configured, otherwise the hook relay.
func (s *Service) serviceRelayURL() string {
	graspRelayURL, hookRelayURL := s.cfg.GraspRelayURL, s.cfg.HookRelayURL
	if snapshot := s.policy.Current(); snapshot != nil {
		graspRelayURL, hookRelayURL = snapshot.GraspRelayURL, snapshot.HookRelayURL
	}
	if graspRelayURL != "" {
		return graspRelayURL
	}
	return hookRelayURL
}

// findCloneForService accepts the canonical GRASP-01 npub-form clone URL
// (<graspPublicURL>/<npub>/<percent-encoded-id>.git) when a canonical origin
// is configured, and falls back to legacy clone-prefix matching. Conventional
// Gitea /org/repo.git URLs are never treated as canonical GRASP URLs.
func findCloneForService(tags nostr.Tags, graspPublicURL string, clonePrefix string, npub string, repoID string) (string, bool) {
	if canonical := grasp.CanonicalCloneURL(graspPublicURL, npub, repoID); canonical != "" {
		for _, tag := range tags {
			if len(tag) < 2 || tag[0] != "clone" {
				continue
			}
			for _, value := range tag[1:] {
				clone := strings.TrimRight(value, "/")
				if clone == canonical || decodedEqual(clone, canonical) {
					return canonical, true
				}
			}
		}
		return "", false
	}
	return findCloneForPrefix(tags, clonePrefix)
}

// decodedEqual compares two URLs ignoring percent-encoding differences.
func decodedEqual(a string, b string) bool {
	da, errA := url.PathUnescape(a)
	db, errB := url.PathUnescape(b)
	return errA == nil && errB == nil && da == db
}

func findCloneForPrefix(tags nostr.Tags, clonePrefix string) (string, bool) {
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "clone" {
			continue
		}
		for _, value := range tag[1:] {
			clone := strings.TrimRight(value, "/")
			if strings.HasPrefix(clone, clonePrefix+"/") {
				return clone, true
			}
		}
	}
	return "", false
}

func hasRelayForService(tags nostr.Tags, serviceRelayURL string) bool {
	serviceRelayURL = normalizeRelayURL(serviceRelayURL)
	if serviceRelayURL == "" {
		return false
	}
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "relays" {
			continue
		}
		for _, relayURL := range tag[1:] {
			if normalizeRelayURL(relayURL) == serviceRelayURL {
				return true
			}
		}
	}
	return false
}

func normalizeRelayURL(relayURL string) string {
	return strings.TrimRight(strings.TrimSpace(relayURL), "/")
}

func cloneMatchesRepoID(cloneURL string, repoID string) bool {
	cloneURL = strings.TrimRight(cloneURL, "/")
	decoded, err := url.PathUnescape(cloneURL)
	if err != nil {
		return false
	}
	return strings.HasSuffix(decoded, "/"+repoID+".git")
}

package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/hooks"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const KindRepositoryAnnouncement = 30617

type Service struct {
	cfg       config.Config
	store     *store.SQLiteStore
	gitea     *gitea.Client
	logger    *slog.Logger
	installer *hooks.Installer
}

type Result struct {
	Npub   string `json:"npub"`
	RepoID string `json:"repo_id"`
	Owner  string `json:"owner"`
	Repo   string `json:"repo"`
	Event  string `json:"event"`
}

func New(cfg config.Config, st *store.SQLiteStore, g *gitea.Client, installer *hooks.Installer, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, store: st, gitea: g, installer: installer, logger: logger}
}

func (s *Service) HandleAnnouncementEvent(ctx context.Context, ev *nostr.Event, relayURL string) error {
	metrics.IncAnnouncementReceived()
	if ev == nil {
		metrics.IncAnnouncementRejected()
		return errors.New("nil event")
	}
	if ev.Kind != KindRepositoryAnnouncement {
		return nil
	}

	processed, err := s.store.EventProcessed(ctx, ev.ID)
	if err != nil {
		metrics.IncAnnouncementRejected()
		return err
	}
	if processed {
		return nil
	}

	if strings.TrimSpace(ev.ID) == "" || strings.TrimSpace(ev.PubKey) == "" {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("invalid announcement: missing id/pubkey")
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("announcement cryptographic validation failed: %w", err)
	}

	npub, err := nip19.EncodePublicKey(ev.PubKey)
	if err != nil {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("encode npub from pubkey: %w", err)
	}

	repoID := getTagValue(ev.Tags, "d")
	if repoID == "" {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("missing d tag for announcement %s", ev.ID)
	}

	cloneURL, ok := findCloneForPrefix(ev.Tags, s.cfg.ClonePrefix)
	if !ok {
		exists, err := s.store.MappingExists(ctx, npub, repoID)
		if err != nil {
			metrics.IncAnnouncementRejected()
			return fmt.Errorf("check existing mapping: %w", err)
		}
		if exists {
			if err := s.gitea.ArchiveRepo(ctx, npub, repoID); err != nil {
				metrics.IncAnnouncementRejected()
				return fmt.Errorf("archive repo %s/%s after clone tag removal: %w", npub, repoID, err)
			}
			_ = s.store.MarkEventProcessed(ctx, ev.ID, ev.PubKey, ev.Kind)
			s.logger.Info("archived repository due to clone tag removal", "npub", npub, "repo_id", repoID, "event", ev.ID)
			return nil
		}
		return nil
	}
	if !cloneMatchesRepoID(cloneURL, repoID) {
		metrics.IncAnnouncementRejected()
		return fmt.Errorf("announcement %s clone URL does not match repo id %s", ev.ID, repoID)
	}

	if err := s.provisionFromAnnouncement(ctx, npub, ev.PubKey, repoID, cloneURL, ev.ID, relayURL); err != nil {
		metrics.IncAnnouncementRejected()
		return err
	}

	if err := s.store.MarkEventProcessed(ctx, ev.ID, ev.PubKey, ev.Kind); err != nil {
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
		decoded, ok := value.(string)
		if !ok {
			metrics.IncManualProvisionFailures()
			return Result{}, fmt.Errorf("invalid decoded npub value")
		}
		pubkey = decoded
	}

	cloneURL := fmt.Sprintf("%s/%s/%s.git", s.cfg.ClonePrefix, npub, repoID)
	err := s.provisionFromAnnouncement(ctx, npub, pubkey, repoID, cloneURL, "manual", "manual")
	if err != nil {
		metrics.IncManualProvisionFailures()
		return Result{}, err
	}

	return Result{Npub: npub, RepoID: repoID, Owner: npub, Repo: repoID, Event: "manual"}, nil
}

func (s *Service) provisionFromAnnouncement(ctx context.Context, npub string, pubkey string, repoID string, cloneURL string, sourceEvent string, sourceRelay string) error {
	if err := s.validatePolicy(ctx, npub, pubkey); err != nil {
		return err
	}

	if err := s.gitea.EnsureOrg(ctx, npub); err != nil {
		return fmt.Errorf("ensure org %s: %w", npub, err)
	}

	repo, err := s.gitea.EnsureRepo(ctx, npub, repoID)
	if err != nil {
		return fmt.Errorf("ensure repo %s/%s: %w", npub, repoID, err)
	}

	mapping := store.Mapping{
		Npub:        npub,
		RepoID:      repoID,
		Pubkey:      pubkey,
		Owner:       npub,
		RepoName:    repoID,
		GiteaRepoID: repo.ID,
		CloneURL:    cloneURL,
		SourceEvent: sourceEvent,
	}
	if err := s.store.UpsertMapping(ctx, mapping); err != nil {
		return fmt.Errorf("save mapping: %w", err)
	}

	if s.installer != nil {
		if err := s.installer.Install(npub, repoID); err != nil {
			return fmt.Errorf("install pre-receive hook: %w", err)
		}
	}

	s.logger.Info("provisioned repository", "npub", npub, "repo_id", repoID, "relay", sourceRelay, "event", sourceEvent)
	return nil
}

func (s *Service) validatePolicy(ctx context.Context, npub string, pubkey string) error {
	if s.cfg.AllowlistEnabled() {
		if _, ok := s.cfg.PubkeyAllowlist[pubkey]; !ok {
			if _, ok := s.cfg.PubkeyAllowlist[npub]; !ok {
				return fmt.Errorf("pubkey %s not allowlisted", pubkey)
			}
		}
	}

	if s.cfg.ProvisionRateLimit > 0 {
		count, err := s.store.ProvisionCountSince(ctx, pubkey, time.Now().Add(-1*time.Hour))
		if err != nil {
			return err
		}
		if count >= s.cfg.ProvisionRateLimit {
			return fmt.Errorf("rate limit exceeded for pubkey %s", pubkey)
		}
	}

	return nil
}

func getTagValue(tags nostr.Tags, key string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

func findCloneForPrefix(tags nostr.Tags, clonePrefix string) (string, bool) {
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != "clone" {
			continue
		}
		clone := strings.TrimRight(tag[1], "/")
		if strings.HasPrefix(clone, clonePrefix+"/") {
			return clone, true
		}
	}
	return "", false
}

func cloneMatchesRepoID(cloneURL string, repoID string) bool {
	cloneURL = strings.TrimRight(cloneURL, "/")
	return strings.HasSuffix(cloneURL, "/"+repoID+".git")
}

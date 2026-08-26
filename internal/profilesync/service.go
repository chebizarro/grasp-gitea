// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package profilesync keeps linked users' Gitea profiles in sync with their
// Nostr kind:0 (NIP-01/NIP-24) metadata: display name, bio, website, and
// custom avatar. It fetches each linked pubkey's latest verified kind:0 on a
// periodic sweep (and on identity resolution), deduplicates by the event's
// created_at, and applies bounded changes to the pinned Gitea user. Avatars
// require acting as the user, so an ephemeral write:user PAT is minted and
// durably tracked for delete-after-use.
package profilesync

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/metrics"
	"github.com/sharegap/grasp-gitea/internal/nostrprofile"
	"github.com/sharegap/grasp-gitea/internal/policy"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	// clockSkewLimit rejects a kind:0 dated too far in the future, so a
	// signer clock error cannot pin a profile until an even newer event.
	clockSkewLimit = 10 * time.Minute
	// patCleanupTimeout bounds the detached cleanup of an ephemeral PAT.
	patCleanupTimeout = 30 * time.Second
	// syncAttemptTimeout bounds a single per-user sync (relay fetch + Gitea).
	syncAttemptTimeout = 60 * time.Second
	// ephemeralPATScope is the minimum scope needed to set a user avatar.
	ephemeralPATScope = "write:user"
	sweepPageSize     = 200
)

// ErrCleanupPending means a user's sync was deferred because a prior
// ephemeral avatar PAT is still awaiting confirmed deletion. It is expected
// back-pressure, logged quietly, not an outage.
var ErrCleanupPending = errors.New("profile sync deferred: ephemeral PAT cleanup pending")

// Store is the persistence the service needs. *store.SQLiteStore satisfies it.
type Store interface {
	GetIdentityLinkByPubkey(ctx context.Context, pubkey string) (store.NostrIdentityLink, error)
	ListIdentityLinksAfter(ctx context.Context, afterPubkey string, limit int) ([]store.NostrIdentityLink, error)
	GetProfileSyncCursor(ctx context.Context, pubkey string, giteaUserID int64) (store.ProfileSyncCursor, error)
	MarkNostrProfileSynced(ctx context.Context, pubkey string, giteaUserID int64, eventID string, eventCreatedAt int64, syncedAt time.Time) (bool, error)
	ReserveProfileSyncPATCleanup(ctx context.Context, rec store.ProfileSyncPATCleanup, now time.Time) error
	SetProfileSyncPATTokenID(ctx context.Context, patName string, tokenID int64) error
	GetProfileSyncPATCleanupForUser(ctx context.Context, giteaUserID int64) (store.ProfileSyncPATCleanup, bool, error)
	ListStaleProfileSyncPATCleanup(ctx context.Context, limit int) ([]store.ProfileSyncPATCleanup, error)
	RecordProfileSyncPATDeleteFailure(ctx context.Context, patName, lastError string) error
	DeleteProfileSyncPATCleanup(ctx context.Context, patName string) error
}

// Gitea is the subset of the Gitea client the service uses.
type Gitea interface {
	GetUser(ctx context.Context, login string) (gitea.User, error)
	UpdateUserProfileFields(ctx context.Context, username string, f gitea.UserProfileFields) error
	CreateUserAccessToken(ctx context.Context, username, tokenName string, scopes []string) (gitea.AccessToken, error)
	DeleteUserAccessToken(ctx context.Context, username, tokenRef string) error
	GetAuthenticatedUserBasic(ctx context.Context, username, pat string) (gitea.User, error)
	SetUserAvatarBasic(ctx context.Context, username, pat string, image []byte) error
	DeleteUserAvatarBasic(ctx context.Context, username, pat string) error
}

// Config parameterizes the service.
type Config struct {
	Interval time.Duration
	Workers  int
}

// Service runs the profile-sync sweeps, worker pool, and PAT reconciler.
type Service struct {
	store     Store
	gitea     Gitea
	relayURLs []string
	interval  time.Duration
	workers   int
	policy    *policy.Store
	logger    *slog.Logger
	now       func() time.Time

	queue     chan string
	pendingMu sync.Mutex
	pending   map[string]struct{}
	userLocks [64]sync.Mutex

	// fetch and prepareImage are seams for testing; New wires the real
	// relay fetch and safefetch image download.
	fetch        func(ctx context.Context, pubkey string) (snapshot, error)
	prepareImage func(ctx context.Context, pictureURL string) ([]byte, error)
}

// snapshot is the service's internal view of a kind:0, decoupled from the
// nostrprofile package so tests can inject one.
type snapshot struct {
	displayName string
	about       string
	website     string
	picture     string
	eventID     string
	createdAt   int64
}

func (s snapshot) profile() nostrprofile.Profile {
	return nostrprofile.Profile{
		DisplayName: s.displayName, About: s.about, Website: s.website, Picture: s.picture,
	}
}

// New builds a Service. relayURLs must be non-empty when enabled.
func New(cfg Config, st Store, gc Gitea, relayURLs []string, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}
	svc := &Service{
		store:     st,
		gitea:     gc,
		relayURLs: relayURLs,
		interval:  cfg.Interval,
		workers:   cfg.Workers,
		logger:    logger.With("component", "profilesync"),
		now:       func() time.Time { return time.Now() },
		queue:     make(chan string, 1024),
		pending:   make(map[string]struct{}),
	}
	svc.fetch = func(ctx context.Context, pubkey string) (snapshot, error) {
		relayURLs := svc.relayURLs
		if snapshot := svc.policy.Current(); snapshot != nil {
			relayURLs = snapshot.RelayURLs
		}
		snap, err := nostrprofile.FetchLatest(ctx, pubkey, relayURLs)
		if err != nil {
			return snapshot{}, err
		}
		return snapshot{
			displayName: snap.Profile.DisplayName, about: snap.Profile.About,
			website: snap.Profile.Website, picture: snap.Profile.Picture,
			eventID: snap.EventID, createdAt: snap.CreatedAt,
		}, nil
	}
	svc.prepareImage = gitea.PrepareUserAvatarImage
	return svc
}

func (s *Service) SetPolicyStore(store *policy.Store) { s.policy = store }

func (s *Service) liveSettings() (bool, time.Duration, int) {
	if snapshot := s.policy.Current(); snapshot != nil {
		return snapshot.ProfileSyncEnabled, snapshot.ProfileSyncInterval, snapshot.ProfileSyncWorkers
	}
	return true, s.interval, s.workers
}

// Enqueue schedules a pubkey for sync, coalescing duplicates. Non-blocking:
// on a full queue the periodic sweep remains the recovery path.
func (s *Service) Enqueue(pubkey string) {
	pubkey = strings.TrimSpace(pubkey)
	if pubkey == "" {
		return
	}
	s.pendingMu.Lock()
	if _, dup := s.pending[pubkey]; dup {
		s.pendingMu.Unlock()
		return
	}
	s.pending[pubkey] = struct{}{}
	s.pendingMu.Unlock()

	select {
	case s.queue <- pubkey:
	default:
		// Queue full: drop the pending mark so a later trigger re-enqueues.
		s.pendingMu.Lock()
		delete(s.pending, pubkey)
		s.pendingMu.Unlock()
	}
}

// Run starts workers, the periodic sweeper, and the PAT reconciler until ctx
// is cancelled.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	workerCount := s.workers
	if s.policy != nil {
		workerCount = 32
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			s.worker(ctx, index)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.sweeper(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.reconciler(ctx)
	}()
	wg.Wait()
}

func (s *Service) worker(ctx context.Context, index int) {
	for {
		changes := s.policy.Changes()
		enabled, _, workers := s.liveSettings()
		if !enabled || index >= workers {
			select {
			case <-ctx.Done():
				return
			case <-changes:
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changes:
			continue
		case pubkey := <-s.queue:
			s.pendingMu.Lock()
			delete(s.pending, pubkey)
			s.pendingMu.Unlock()

			attemptCtx, cancel := context.WithTimeout(ctx, syncAttemptTimeout)
			err := s.SyncPubkey(attemptCtx, pubkey)
			cancel()
			switch {
			case err == nil:
			case errors.Is(err, ErrCleanupPending):
				s.logger.Debug("profile sync deferred", "pubkey", pubkey)
			default:
				s.logger.Warn("profile sync failed", "pubkey", pubkey, "error", err)
			}
		}
	}
}

func (s *Service) sweeper(ctx context.Context) {
	s.runPeriodic(ctx, s.sweep)
}

// sweep keyset-pages every linked identity and enqueues it with back-pressure:
// unlike login notifications (which may drop), the sweep BLOCKS on a full
// queue so every linked user gets a guaranteed attempt and tail users are
// never starved.
func (s *Service) sweep(ctx context.Context) {
	after := ""
	for {
		links, err := s.store.ListIdentityLinksAfter(ctx, after, sweepPageSize)
		if err != nil {
			s.logger.Warn("profile sync sweep page failed", "error", err)
			return
		}
		if len(links) == 0 {
			return
		}
		for _, link := range links {
			if !s.enqueueBlocking(ctx, link.Pubkey) {
				return // context cancelled
			}
		}
		after = links[len(links)-1].Pubkey
	}
}

// enqueueBlocking coalesces like Enqueue but waits for queue space rather
// than dropping. Returns false if ctx is cancelled while waiting.
func (s *Service) enqueueBlocking(ctx context.Context, pubkey string) bool {
	s.pendingMu.Lock()
	if _, dup := s.pending[pubkey]; dup {
		s.pendingMu.Unlock()
		return true
	}
	s.pending[pubkey] = struct{}{}
	s.pendingMu.Unlock()

	select {
	case s.queue <- pubkey:
		return true
	case <-ctx.Done():
		s.pendingMu.Lock()
		delete(s.pending, pubkey)
		s.pendingMu.Unlock()
		return false
	}
}

func (s *Service) reconciler(ctx context.Context) {
	s.runPeriodic(ctx, s.reconcilePATs)
}

func (s *Service) runPeriodic(ctx context.Context, action func(context.Context)) {
	for {
		changes := s.policy.Changes()
		enabled, interval, _ := s.liveSettings()
		if enabled {
			action(ctx)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-changes:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}

func (s *Service) userLock(giteaUserID int64) *sync.Mutex {
	return &s.userLocks[uint64(giteaUserID)%uint64(len(s.userLocks))]
}

// SyncPubkey synchronizes one linked pubkey's Gitea profile from its latest
// kind:0. It is idempotent and safe to call repeatedly.
func (s *Service) SyncPubkey(ctx context.Context, pubkey string) error {
	link, err := s.store.GetIdentityLinkByPubkey(ctx, pubkey)
	if err != nil {
		if isNoRows(err) {
			return nil // no longer linked
		}
		return fmt.Errorf("load identity link: %w", err)
	}

	lock := s.userLock(link.GiteaUserID)
	lock.Lock()
	defer lock.Unlock()

	// Re-read under the lock: the link is authoritative for the cursor and id.
	link, err = s.store.GetIdentityLinkByPubkey(ctx, pubkey)
	if err != nil {
		if isNoRows(err) {
			return nil
		}
		return err
	}

	// Never mint a new ephemeral PAT while a prior one may still be live.
	if rec, ok, err := s.store.GetProfileSyncPATCleanupForUser(ctx, link.GiteaUserID); err != nil {
		return err
	} else if ok {
		s.cleanupEphemeralPAT(ctx, rec)
		// Do not proceed while a prior ephemeral PAT may be live. This is
		// expected back-pressure, not an outage — signal it distinctly so
		// callers can log it quietly.
		return fmt.Errorf("%w for user %d", ErrCleanupPending, link.GiteaUserID)
	}

	cursor, err := s.store.GetProfileSyncCursor(ctx, pubkey, link.GiteaUserID)
	if err != nil {
		return err
	}

	snap, err := s.fetch(ctx, pubkey)
	if err != nil {
		if errors.Is(err, nostrprofile.ErrProfileNotFound) {
			return nil // no profile to apply; leave Gitea and cursor as-is
		}
		// Relay outage: retry on a later trigger, but keep it observable.
		metrics.IncProfileSyncRelayFailure()
		return nil
	}
	if snap.createdAt <= cursor.EventCreatedAt {
		return nil // already applied this or a newer event
	}
	if snap.createdAt > s.now().Add(clockSkewLimit).Unix() {
		s.logger.Warn("ignoring future-dated kind:0", "pubkey", pubkey, "created_at", snap.createdAt)
		return nil // do not advance the cursor
	}

	// Verify the live username still resolves to the pinned id before writing.
	live, err := s.gitea.GetUser(ctx, link.GiteaUser)
	if err != nil {
		return fmt.Errorf("verify gitea user: %w", err)
	}
	if live.ID != link.GiteaUserID {
		return fmt.Errorf("identity mismatch: gitea user %q now id %d, linked id %d",
			link.GiteaUser, live.ID, link.GiteaUserID)
	}

	// Prepare the avatar before touching Gitea, so an ephemeral PAT is never
	// minted while a slow image download is in flight.
	var avatarImage []byte
	avatarAction := avatarNone
	if snap.picture != "" {
		img, imgErr := s.prepareImage(ctx, snap.picture)
		switch {
		case imgErr == nil:
			avatarImage, avatarAction = img, avatarSet
		case errors.Is(imgErr, gitea.ErrImageInvalid):
			s.logger.Warn("skipping invalid profile picture; syncing text only",
				"pubkey", pubkey, "error", imgErr)
			avatarAction = avatarNone
		default: // transient
			return fmt.Errorf("avatar download: %w", imgErr)
		}
	} else {
		avatarAction = avatarDelete
	}

	// Text metadata via admin edit.
	fields := gitea.NormalizeUserProfile(snap.profile())
	if err := s.gitea.UpdateUserProfileFields(ctx, link.GiteaUser, fields); err != nil {
		return fmt.Errorf("update user profile fields: %w", err)
	}

	if avatarAction != avatarNone {
		if err := s.applyAvatar(ctx, link, avatarAction, avatarImage); err != nil {
			return err // cursor not advanced; retry later
		}
	}

	if _, err := s.store.MarkNostrProfileSynced(ctx, pubkey, link.GiteaUserID, snap.eventID, snap.createdAt, s.now().UTC()); err != nil {
		return fmt.Errorf("advance profile cursor: %w", err)
	}
	metrics.IncProfileSynced()
	s.logger.Info("synced Nostr profile into Gitea", "pubkey", pubkey, "gitea_user", link.GiteaUser)
	return nil
}

type avatarOp int

const (
	avatarNone avatarOp = iota
	avatarSet
	avatarDelete
)

// applyAvatar mints an ephemeral write:user PAT (durably tracked), verifies it
// authenticates as the pinned user, applies the avatar op, and always deletes
// the PAT afterward on a detached context.
func (s *Service) applyAvatar(ctx context.Context, link store.NostrIdentityLink, op avatarOp, image []byte) error {
	patName, err := ephemeralPATName(link.GiteaUserID)
	if err != nil {
		return err
	}
	rec := store.ProfileSyncPATCleanup{
		PATName: patName, GiteaUserID: link.GiteaUserID, GiteaUser: link.GiteaUser,
	}
	if err := s.store.ReserveProfileSyncPATCleanup(ctx, rec, s.now().UTC()); err != nil {
		return fmt.Errorf("reserve ephemeral PAT cleanup: %w", err)
	}

	created, createErr := s.gitea.CreateUserAccessToken(ctx, link.GiteaUser, patName, []string{ephemeralPATScope})

	// Past this point a PAT may exist; all cleanup runs detached so a
	// cancelled request cannot strand a live credential.
	cleanupCtx, cancel := context.WithoutCancel(ctx), func() {}
	cleanupCtx, cancel = context.WithTimeout(cleanupCtx, patCleanupTimeout)
	defer cancel()

	if createErr != nil {
		// Ambiguous: Gitea may have committed the PAT. Delete by reserved name.
		s.cleanupEphemeralPAT(cleanupCtx, rec)
		return fmt.Errorf("mint ephemeral PAT: %w", createErr)
	}
	if created.ID > 0 {
		if err := s.store.SetProfileSyncPATTokenID(ctx, patName, created.ID); err != nil {
			s.logger.Warn("could not persist ephemeral PAT token id", "error", err)
		}
		rec.GiteaTokenID = created.ID
	}

	err = s.useEphemeralPAT(ctx, link, created.Token, op, image)
	// Always delete the PAT, success or failure.
	s.cleanupEphemeralPAT(cleanupCtx, rec)
	return err
}

// useEphemeralPAT verifies the PAT's subject then performs the avatar op.
func (s *Service) useEphemeralPAT(ctx context.Context, link store.NostrIdentityLink, pat string, op avatarOp, image []byte) error {
	who, err := s.gitea.GetAuthenticatedUserBasic(ctx, link.GiteaUser, pat)
	if err != nil {
		return fmt.Errorf("verify ephemeral PAT subject: %w", err)
	}
	if who.ID != link.GiteaUserID {
		return fmt.Errorf("ephemeral PAT authenticates as id %d, expected %d", who.ID, link.GiteaUserID)
	}
	switch op {
	case avatarSet:
		return s.gitea.SetUserAvatarBasic(ctx, link.GiteaUser, pat, image)
	case avatarDelete:
		return s.gitea.DeleteUserAvatarBasic(ctx, link.GiteaUser, pat)
	}
	return nil
}

// cleanupEphemeralPAT deletes the PAT (by id if known, else reserved name)
// and removes the cleanup row once deletion is confirmed. A 404 is success.
func (s *Service) cleanupEphemeralPAT(ctx context.Context, rec store.ProfileSyncPATCleanup) {
	ref := rec.PATName
	if rec.GiteaTokenID > 0 {
		ref = fmt.Sprintf("%d", rec.GiteaTokenID)
	}
	if err := s.gitea.DeleteUserAccessToken(ctx, rec.GiteaUser, ref); err != nil && !gitea.IsNotFound(err) {
		if recErr := s.store.RecordProfileSyncPATDeleteFailure(ctx, rec.PATName, err.Error()); recErr != nil {
			s.logger.Warn("could not record ephemeral PAT delete failure", "error", recErr)
		}
		s.logger.Warn("ephemeral profile-sync PAT deletion failed; will retry", "pat", rec.PATName, "error", err)
		metrics.IncProfileSyncPATCleanupFailures()
		return
	}
	if err := s.store.DeleteProfileSyncPATCleanup(ctx, rec.PATName); err != nil {
		s.logger.Warn("could not clear ephemeral PAT cleanup row", "pat", rec.PATName, "error", err)
	}
}

// reconcilePATs sweeps outstanding cleanup rows and retries deletion.
func (s *Service) reconcilePATs(ctx context.Context) {
	rows, err := s.store.ListStaleProfileSyncPATCleanup(ctx, sweepPageSize)
	if err != nil {
		s.logger.Warn("ephemeral PAT reconcile scan failed", "error", err)
		return
	}
	for _, rec := range rows {
		lock := s.userLock(rec.GiteaUserID)
		lock.Lock()
		// Re-read under the lock: SyncPubkey may have cleaned it up.
		current, ok, err := s.store.GetProfileSyncPATCleanupForUser(ctx, rec.GiteaUserID)
		if err != nil || !ok || current.PATName != rec.PATName {
			lock.Unlock()
			continue
		}
		s.cleanupEphemeralPAT(ctx, current)
		lock.Unlock()
	}
}

func ephemeralPATName(giteaUserID int64) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate ephemeral PAT name: %w", err)
	}
	return fmt.Sprintf("grasp-profile-%d-%s", giteaUserID, base64.RawURLEncoding.EncodeToString(buf)), nil
}

func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

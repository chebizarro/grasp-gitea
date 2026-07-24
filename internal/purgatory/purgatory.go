// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package purgatory implements GRASP-01 durable purgatory: accepted
// repository events (kind 30617/30618 state, 1618/1619 PRs) whose referenced
// Git objects have not yet arrived are retained durably — surviving process
// restarts — but excluded from normal relay queries. They are released
// atomically into the relay store once the required Git objects appear, and
// discarded after TTL if the data never arrives.
package purgatory

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

// DefaultTTL is the GRASP-01 purgatory retention window.
const DefaultTTL = 30 * time.Minute

// Store is the durable persistence needed by the purgatory service.
type Store interface {
	UpsertPurgatoryEvent(ctx context.Context, ev store.PurgatoryEvent) error
	ListPurgatoryEvents(ctx context.Context) ([]store.PurgatoryEvent, error)
	DeletePurgatoryEvent(ctx context.Context, eventID string) error
}

// ReleaseFunc atomically publishes a previously-held event into the relay
// store. Implementations must preserve NIP-01 replaceable-event ordering
// (the eventstore replace path already does).
type ReleaseFunc func(ctx context.Context, ev nostr.Event) error

// ObjectChecker reports whether a git object exists in a bare repository.
type ObjectChecker func(ctx context.Context, repoPath string, sha string) bool

type Service struct {
	store        Store
	release      ReleaseFunc
	objectExists ObjectChecker
	ttl          time.Duration
	now          func() time.Time
	logger       *slog.Logger
}

type Option func(*Service)

func WithTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

func WithObjectChecker(check ObjectChecker) Option {
	return func(s *Service) {
		if check != nil {
			s.objectExists = check
		}
	}
}

func New(st Store, release ReleaseFunc, logger *slog.Logger, opts ...Option) *Service {
	s := &Service{
		store:        st,
		release:      release,
		objectExists: gitObjectExists,
		ttl:          DefaultTTL,
		now:          time.Now,
		logger:       logger.With("component", "purgatory"),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RequiredSHAs returns the git object SHAs an event references: state-event
// branch/tag tips for kind 30618, the PR tip commit (c tag) for 1618/1619.
// Kinds with no git-object references return an empty slice.
func RequiredSHAs(ev *nostr.Event) []string {
	switch int(ev.Kind) {
	case relay.KindRepositoryState:
		state := nip34.ParseRepositoryState(*ev)
		seen := map[string]struct{}{}
		var shas []string
		add := func(sha string) {
			if sha == "" || strings.Repeat("0", 40) == sha {
				return
			}
			if _, ok := seen[sha]; ok {
				return
			}
			seen[sha] = struct{}{}
			shas = append(shas, sha)
		}
		for _, sha := range state.Branches {
			add(sha)
		}
		for tag, sha := range state.Tags {
			if strings.HasSuffix(tag, "^{}") {
				continue
			}
			add(sha)
		}
		return shas
	case relay.KindPROpen, relay.KindPRUpdate:
		if tip := ev.Tags.Find("c"); tip != nil && len(tip) >= 2 && tip[1] != "" {
			return []string{tip[1]}
		}
		return nil
	default:
		return nil
	}
}

// Hold decides whether an event must enter purgatory. If any required git
// object is missing from repoPath, the event is durably recorded and Hold
// returns true; the caller must then acknowledge acceptance without serving
// the event. Events with no git references (or with all objects present)
// return false and flow to the relay store normally.
func (s *Service) Hold(ctx context.Context, ev *nostr.Event, repoPath string) (bool, error) {
	required := RequiredSHAs(ev)
	if len(required) == 0 {
		return false, nil
	}
	missing := false
	for _, sha := range required {
		if !s.objectExists(ctx, repoPath, sha) {
			missing = true
			break
		}
	}
	if !missing {
		return false, nil
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return false, fmt.Errorf("marshal purgatory event: %w", err)
	}
	dTag := ""
	if d := ev.Tags.Find("d"); d != nil && len(d) >= 2 {
		dTag = d[1]
	}
	rec := store.PurgatoryEvent{
		EventID:      ev.ID.Hex(),
		Pubkey:       ev.PubKey.Hex(),
		Kind:         int(ev.Kind),
		DTag:         dTag,
		EventJSON:    string(raw),
		RequiredSHAs: required,
		RepoPath:     repoPath,
		AcceptedAt:   s.now().UTC(),
	}
	if err := s.store.UpsertPurgatoryEvent(ctx, rec); err != nil {
		return false, err
	}
	s.logger.Info("event held in purgatory awaiting git data", "event", rec.EventID, "kind", rec.Kind, "missing_objects", len(required))
	return true, nil
}

// Sweep releases events whose git objects have arrived and expires events
// older than the TTL. Call it periodically; it is restart-safe because the
// backlog lives in the durable store.
func (s *Service) Sweep(ctx context.Context) error {
	pending, err := s.store.ListPurgatoryEvents(ctx)
	if err != nil {
		return err
	}
	var errs []string
	for _, rec := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.now().UTC().Sub(rec.AcceptedAt.UTC()) > s.ttl {
			if err := s.store.DeletePurgatoryEvent(ctx, rec.EventID); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			s.logger.Info("purgatory event expired without git data", "event", rec.EventID, "kind", rec.Kind)
			continue
		}
		ready := true
		for _, sha := range rec.RequiredSHAs {
			if !s.objectExists(ctx, rec.RepoPath, sha) {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}
		var ev nostr.Event
		if err := json.Unmarshal([]byte(rec.EventJSON), &ev); err != nil {
			errs = append(errs, fmt.Sprintf("decode %s: %v", rec.EventID, err))
			_ = s.store.DeletePurgatoryEvent(ctx, rec.EventID)
			continue
		}
		// Release first, then delete: a crash between the two re-releases on
		// the next sweep, which the eventstore treats as a duplicate — the
		// event is never lost.
		if err := s.release(ctx, ev); err != nil {
			errs = append(errs, fmt.Sprintf("release %s: %v", rec.EventID, err))
			continue
		}
		if err := s.store.DeletePurgatoryEvent(ctx, rec.EventID); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		s.logger.Info("purgatory event released", "event", rec.EventID, "kind", rec.Kind)
	}
	if len(errs) > 0 {
		return fmt.Errorf("purgatory sweep: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Run sweeps on an interval until the context ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
				s.logger.Warn("purgatory sweep failed", "error", err)
			}
		}
	}
}

func gitObjectExists(ctx context.Context, repoPath string, sha string) bool {
	if repoPath == "" || sha == "" {
		return false
	}
	return exec.CommandContext(ctx, "git", "--git-dir", repoPath, "cat-file", "-e", sha).Run() == nil
}

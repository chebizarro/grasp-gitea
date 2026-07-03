// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package refsnostr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/sharegap/grasp-gitea/internal/gitea"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	RefPrefix            = "refs/nostr/"
	DefaultAcceptanceTTL = 20 * time.Minute
	DefaultSweepInterval = 1 * time.Minute
)

var ErrDifferingTip = errors.New("relay event lists a different refs/nostr tip")

type Store interface {
	ListPendingNostrRefsOlderThan(ctx context.Context, cutoff time.Time) ([]store.PendingNostrRef, error)
	DeletePendingNostrRef(ctx context.Context, giteaRepoID int64, eventID string) error
}

type PRChecker interface {
	HasAcceptedPRWithTip(ctx context.Context, eventID, tipSHA string) (bool, error)
}

type RefDeleter interface {
	DeleteNostrRef(ctx context.Context, ref store.PendingNostrRef) error
}

type Clock func() time.Time

type Reaper struct {
	store    Store
	checker  PRChecker
	deleter  RefDeleter
	logger   *slog.Logger
	now      Clock
	ttl      time.Duration
	interval time.Duration
}

type Option func(*Reaper)

func WithClock(now Clock) Option {
	return func(r *Reaper) {
		if now != nil {
			r.now = now
		}
	}
}

func WithTTL(ttl time.Duration) Option {
	return func(r *Reaper) {
		if ttl > 0 {
			r.ttl = ttl
		}
	}
}

func WithSweepInterval(interval time.Duration) Option {
	return func(r *Reaper) {
		if interval > 0 {
			r.interval = interval
		}
	}
}

func NewReaper(st Store, checker PRChecker, deleter RefDeleter, logger *slog.Logger, opts ...Option) *Reaper {
	r := &Reaper{
		store:    st,
		checker:  checker,
		deleter:  deleter,
		logger:   logger,
		now:      time.Now,
		ttl:      DefaultAcceptanceTTL,
		interval: DefaultSweepInterval,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Reaper) Run(ctx context.Context) {
	if r == nil || r.store == nil || r.checker == nil || r.deleter == nil {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Sweep(ctx); err != nil {
				r.warn("refs/nostr reaper sweep failed", "error", err)
			}
		}
	}
}

func (r *Reaper) Sweep(ctx context.Context) error {
	if r == nil || r.store == nil || r.checker == nil || r.deleter == nil {
		return nil
	}
	cutoff := r.now().UTC().Add(-r.ttl)
	pending, err := r.store.ListPendingNostrRefsOlderThan(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("list pending refs/nostr refs: %w", err)
	}

	for _, ref := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}

		matched, err := r.checker.HasAcceptedPRWithTip(ctx, ref.EventID, ref.TipSHA)
		if err != nil {
			r.warn("refs/nostr relay check failed; keeping pending ref", "event_id", ref.EventID, "repo", ref.Owner+"/"+ref.RepoName, "error", err)
			continue
		}
		if matched {
			if err := r.store.DeletePendingNostrRef(ctx, ref.GiteaRepoID, ref.EventID); err != nil {
				r.warn("failed to clear satisfied refs/nostr pending row", "event_id", ref.EventID, "repo", ref.Owner+"/"+ref.RepoName, "error", err)
			}
			continue
		}

		if err := r.deleter.DeleteNostrRef(ctx, ref); err != nil {
			r.warn("failed to delete stale refs/nostr ref", "event_id", ref.EventID, "repo", ref.Owner+"/"+ref.RepoName, "tip", ref.TipSHA, "error", err)
			continue
		}
		if err := r.store.DeletePendingNostrRef(ctx, ref.GiteaRepoID, ref.EventID); err != nil {
			r.warn("failed to clear deleted refs/nostr pending row", "event_id", ref.EventID, "repo", ref.Owner+"/"+ref.RepoName, "error", err)
		}
	}
	return nil
}

func (r *Reaper) warn(msg string, args ...any) {
	if r != nil && r.logger != nil {
		r.logger.Warn(msg, args...)
	}
}

type GitRefDeleter struct {
	RepositoriesDir string
}

func NewGitRefDeleter(repositoriesDir string) *GitRefDeleter {
	return &GitRefDeleter{RepositoriesDir: repositoriesDir}
}

func (d *GitRefDeleter) DeleteNostrRef(ctx context.Context, ref store.PendingNostrRef) error {
	if d == nil || d.RepositoriesDir == "" {
		return fmt.Errorf("repositories dir is not configured")
	}
	repoPath := filepath.Join(d.RepositoriesDir, ref.Owner, ref.RepoName+".git")
	return gitea.DeleteBareRef(ctx, repoPath, RefPrefix+ref.EventID)
}

type EventFetcher interface {
	FetchEvent(ctx context.Context, id string) (*nostr.Event, error)
}

func FetchEventForTip(ctx context.Context, fetcher EventFetcher, eventID, tipSHA string) (*nostr.Event, error) {
	if fetcher == nil {
		return nil, nil
	}
	ev, err := fetcher.FetchEvent(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if EventListsDifferentTip(ev, tipSHA) {
		return ev, ErrDifferingTip
	}
	return ev, nil
}

func EventListsDifferentTip(ev *nostr.Event, tipSHA string) bool {
	if ev == nil || tipSHA == "" {
		return false
	}
	seenCTag := false
	for _, tag := range ev.Tags {
		if len(tag) < 2 || tag[0] != "c" {
			continue
		}
		seenCTag = true
		if tag[1] == tipSHA {
			return false
		}
	}
	return seenCTag
}

func EventIsAcceptedPRWithTip(ev *nostr.Event, eventID, tipSHA string) bool {
	if ev == nil || ev.ID != eventID {
		return false
	}
	if ev.Kind != relay.KindPROpen && ev.Kind != relay.KindPRUpdate {
		return false
	}
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "c" && tag[1] == tipSHA {
			return true
		}
	}
	return false
}

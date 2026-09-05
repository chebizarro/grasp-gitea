// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nip05affiliation

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math/rand"
	"time"

	"github.com/sharegap/grasp-gitea/internal/nip05resolve"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	DefaultInterval = 15 * time.Minute
	identityBatch   = 100
)

type verifier func(context.Context, string, []string) nip05resolve.AffiliationVerification

// Service periodically refreshes directory-only NIP-05 affiliation evidence.
// It never changes repository placement or any authorization state.
type Service struct {
	store     store.AuthStore
	relays    func() []string
	verify    verifier
	interval  time.Duration
	logger    *slog.Logger
	randFloat func() float64
}

func New(st store.AuthStore, relayURLs func() []string, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: st, relays: relayURLs, verify: nip05resolve.VerifyAffiliationFresh,
		interval: DefaultInterval, logger: logger, randFloat: rand.Float64}
}

func (s *Service) Run(ctx context.Context) {
	for {
		s.sweep(ctx)
		delay := s.jitteredInterval()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Service) sweep(ctx context.Context) {
	var after string
	for {
		links, err := s.store.ListIdentityLinksAfter(ctx, after, identityBatch)
		if err != nil {
			s.logger.Warn("NIP-05 affiliation identity scan failed", "error", err)
			return
		}
		for _, link := range links {
			if ctx.Err() != nil {
				return
			}
			s.refresh(ctx, link.Pubkey)
		}
		if len(links) < identityBatch {
			return
		}
		after = links[len(links)-1].Pubkey
	}
}

func (s *Service) refresh(ctx context.Context, pubkey string) {
	checkedAt := time.Now().UTC()
	verification := s.verify(ctx, pubkey, s.relays())
	a := store.DomainAffiliation{
		CanonicalIdentifier: verification.CanonicalIdentifier,
		LocalPart:           verification.LocalPart,
		Host:                verification.Host,
		Pubkey:              verification.Pubkey,
		VerifiedAt:          verification.VerifiedAt,
		CheckedAt:           checkedAt,
		FailureClass:        verification.FailureClass,
		FailureCode:         verification.FailureCode,
		FailureDetail:       verification.FailureDetail,
	}
	if verification.Verified() {
		a.Status = store.DomainAffiliationVerified
	} else {
		if verification.FailureClass == nip05resolve.FailureConfirmedAbsent {
			a.Status = store.DomainAffiliationConfirmedAbsent
		} else {
			a.Status = store.DomainAffiliationStale
		}
		previous, err := s.store.GetDomainAffiliation(ctx, pubkey)
		if err == nil {
			if a.CanonicalIdentifier == "" {
				a.CanonicalIdentifier, a.LocalPart, a.Host = previous.CanonicalIdentifier, previous.LocalPart, previous.Host
			}
			a.VerifiedAt = previous.VerifiedAt
			if a.Status == store.DomainAffiliationStale && !a.VerifiedAt.IsZero() && checkedAt.Sub(a.VerifiedAt) >= time.Hour {
				s.logger.Warn("NIP-05 affiliation has lacked a successful verification for over one hour",
					"pubkey", pubkey, "host", a.Host, "verified_at", a.VerifiedAt)
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("NIP-05 affiliation previous evidence lookup failed", "pubkey", pubkey, "error", err)
		}
	}
	if err := s.store.UpsertDomainAffiliation(ctx, a); err != nil {
		s.logger.Warn("NIP-05 affiliation persistence failed", "pubkey", pubkey, "failure_class", a.FailureClass, "error", err)
	}
}

func (s *Service) jitteredInterval() time.Duration {
	base := s.interval
	if base <= 0 {
		base = DefaultInterval
	}
	// Uniform 80-120% jitter avoids synchronized domain refresh bursts.
	return time.Duration(float64(base) * (0.8 + 0.4*s.randFloat()))
}

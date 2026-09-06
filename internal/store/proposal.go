// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"time"
)

// ProposalState is the durable materialization record for one NIP-34 patch
// thread. RepositoryAddress and RootEventID together identify exactly one
// Gitea pull request.
type ProposalState struct {
	RepositoryAddress   string
	RootEventID         string
	GiteaRepoID         int64
	RootSubmitterPubkey string
	RecoveryNonce       string
	GiteaCreator        string
	GiteaPRID           int64
	GiteaPRNumber       int64
	HeadBranch          string
	HeadRefSHA          string
	BaseBranch          string
	LatestEventID       string
	// ParentEventID is an ephemeral CAS hint used when a signed reply extends
	// the current latest event at the same timestamp. It is not persisted.
	ParentEventID   string
	LatestCreatedAt int64
	UpdatedAt       time.Time
}

// ProposalFailure is retained for operator diagnostics. A later successful
// retry of the same event replaces its failed event state.
type ProposalFailure struct {
	RepositoryAddress string
	RootEventID       string
	EventID           string
	FailureClass      string
	FailureDetail     string
	UpdatedAt         time.Time
}

// ProposalStore persists NIP-34 proposal identity independently from the
// node-local repository mapping store. Both SQLite and Postgres implement it.
type ProposalStore interface {
	// WithProposalLock serializes Git and Gitea side effects for one proposal
	// across every node sharing the backend.
	WithProposalLock(ctx context.Context, repositoryAddress, rootEventID string, fn func(context.Context) error) error
	ReserveProposal(ctx context.Context, proposal ProposalState) (ProposalState, bool, error)
	GetProposal(ctx context.Context, repositoryAddress, rootEventID string) (ProposalState, error)
	GetProposalByEventID(ctx context.Context, eventID string) (ProposalState, error)
	UpsertProposal(ctx context.Context, proposal ProposalState) (advanced bool, err error)
	RecordProposalFailure(ctx context.Context, failure ProposalFailure) error
	GetProposalFailure(ctx context.Context, eventID string) (ProposalFailure, error)
	// DeleteProposalFailure clears one terminal-failure row so a supported
	// operator retry can re-run materialization for a stuck proposal. It
	// does not touch the proposal state row. Idempotent: returns false, nil
	// when no failure row exists.
	DeleteProposalFailure(ctx context.Context, eventID string) (bool, error)
}

var _ ProposalStore = (*SQLiteStore)(nil)
var _ ProposalStore = (*PostgresStore)(nil)

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store

import (
	"context"
	"fmt"
	"time"
)

func (s *PostgresStore) WithProposalLock(ctx context.Context, repositoryAddress, rootEventID string, fn func(context.Context) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire proposal lock connection: %w", err)
	}
	defer conn.Close()
	key := "nip34_proposal:" + repositoryAddress + "\n" + rootEventID
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
		return fmt.Errorf("acquire proposal lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
	}()
	return fn(ctx)
}

func (s *PostgresStore) ReserveProposal(ctx context.Context, p ProposalState) (ProposalState, bool, error) {
	updated := normalizeProposalTime(p.UpdatedAt).Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `INSERT INTO nip34_proposals (`+proposalColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(repository_address,root_event_id) DO NOTHING`, p.RepositoryAddress, p.RootEventID, p.GiteaRepoID, p.RootSubmitterPubkey, p.RecoveryNonce, p.GiteaCreator, p.GiteaPRID, p.GiteaPRNumber, p.HeadBranch, p.HeadRefSHA, p.BaseBranch, p.LatestEventID, p.LatestCreatedAt, updated)
	if err != nil {
		return ProposalState{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ProposalState{}, false, err
	}
	stored, err := s.GetProposal(ctx, p.RepositoryAddress, p.RootEventID)
	return stored, n > 0, err
}

func (s *PostgresStore) GetProposal(ctx context.Context, repositoryAddress, rootEventID string) (ProposalState, error) {
	return scanProposal(s.db.QueryRowContext(ctx, `SELECT `+proposalColumns+` FROM nip34_proposals WHERE repository_address=$1 AND root_event_id=$2`, repositoryAddress, rootEventID))
}

func (s *PostgresStore) GetProposalByEventID(ctx context.Context, eventID string) (ProposalState, error) {
	return scanProposal(s.db.QueryRowContext(ctx, `SELECT p.repository_address,p.root_event_id,p.gitea_repo_id,p.root_submitter_pubkey,p.recovery_nonce,p.gitea_creator,p.gitea_pr_id,p.gitea_pr_number,p.head_branch,p.head_ref_sha,p.base_branch,p.latest_event_id,p.latest_created_at,p.updated_at FROM nip34_proposals p JOIN nip34_proposal_events e ON e.repository_address=p.repository_address AND e.root_event_id=p.root_event_id WHERE e.event_id=$1 AND e.state='materialized'`, eventID))
}

func (s *PostgresStore) UpsertProposal(ctx context.Context, p ProposalState) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	updated := normalizeProposalTime(p.UpdatedAt).Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `INSERT INTO nip34_proposals (`+proposalColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT(repository_address,root_event_id) DO UPDATE SET gitea_repo_id=excluded.gitea_repo_id,root_submitter_pubkey=excluded.root_submitter_pubkey,recovery_nonce=excluded.recovery_nonce,gitea_creator=excluded.gitea_creator,gitea_pr_id=excluded.gitea_pr_id,gitea_pr_number=excluded.gitea_pr_number,head_branch=excluded.head_branch,head_ref_sha=excluded.head_ref_sha,base_branch=excluded.base_branch,latest_event_id=excluded.latest_event_id,latest_created_at=excluded.latest_created_at,updated_at=excluded.updated_at
		WHERE excluded.latest_created_at > nip34_proposals.latest_created_at OR (excluded.latest_created_at = nip34_proposals.latest_created_at AND excluded.latest_event_id < nip34_proposals.latest_event_id) OR ($15 = nip34_proposals.latest_event_id AND excluded.latest_created_at >= nip34_proposals.latest_created_at)`, p.RepositoryAddress, p.RootEventID, p.GiteaRepoID, p.RootSubmitterPubkey, p.RecoveryNonce, p.GiteaCreator, p.GiteaPRID, p.GiteaPRNumber, p.HeadBranch, p.HeadRefSHA, p.BaseBranch, p.LatestEventID, p.LatestCreatedAt, updated, p.ParentEventID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO nip34_proposal_events(event_id,repository_address,root_event_id,state,failure_class,failure_detail,updated_at) VALUES($1,$2,$3,'materialized','','',$4) ON CONFLICT(event_id) DO UPDATE SET repository_address=excluded.repository_address,root_event_id=excluded.root_event_id,state='materialized',failure_class='',failure_detail='',updated_at=excluded.updated_at`, p.LatestEventID, p.RepositoryAddress, p.RootEventID, updated); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *PostgresStore) RecordProposalFailure(ctx context.Context, f ProposalFailure) error {
	updated := normalizeProposalTime(f.UpdatedAt).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO nip34_proposal_events(event_id,repository_address,root_event_id,state,failure_class,failure_detail,updated_at) VALUES($1,$2,$3,'failed',$4,$5,$6) ON CONFLICT(event_id) DO UPDATE SET repository_address=excluded.repository_address,root_event_id=excluded.root_event_id,state='failed',failure_class=excluded.failure_class,failure_detail=excluded.failure_detail,updated_at=excluded.updated_at`, f.EventID, f.RepositoryAddress, f.RootEventID, f.FailureClass, truncateProposalDetail(f.FailureDetail), updated)
	return err
}

func (s *PostgresStore) GetProposalFailure(ctx context.Context, eventID string) (ProposalFailure, error) {
	var f ProposalFailure
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT repository_address,root_event_id,event_id,failure_class,failure_detail,updated_at FROM nip34_proposal_events WHERE event_id=$1 AND state='failed'`, eventID).Scan(&f.RepositoryAddress, &f.RootEventID, &f.EventID, &f.FailureClass, &f.FailureDetail, &updated)
	if err != nil {
		return ProposalFailure{}, err
	}
	f.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return ProposalFailure{}, fmt.Errorf("parse proposal failure updated_at: %w", err)
	}
	return f, nil
}

// DeleteProposalFailure removes a terminal-failure row for one proposal event
// so a supported operator retry can re-run materialization. See the SQLite
// implementation for the full contract. Idempotent.
func (s *PostgresStore) DeleteProposalFailure(ctx context.Context, eventID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nip34_proposal_events WHERE event_id=$1 AND state='failed'`, eventID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

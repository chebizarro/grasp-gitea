package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestWritableUpstreamActivationAndRollbackCAS(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	original := Mapping{Npub: "npub1owner", RepoID: "demo", Pubkey: "ownerhex", Owner: "cascadia", RepoName: "demo", GiteaRepoID: 21, CloneURL: "https://git.example/cascadia/demo.git", SourceEvent: "announcement", HookInstalled: true}
	if err := st.UpsertMapping(ctx, original); err != nil {
		t.Fatal(err)
	}
	original, err = st.GetMapping(ctx, original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	record := WritableUpstreamMigration{Npub: original.Npub, RepoID: original.RepoID, OldOwner: original.Owner, OldRepoName: original.RepoName, OldGiteaRepoID: original.GiteaRepoID, OldCloneURL: original.CloneURL, NewOwner: "cascadia", NewRepoName: "demo-grasp-upstream", NewGiteaRepoID: 57, NewCloneURL: "https://git.example/cascadia/demo-grasp-upstream.git", ExpectedMappingUpdatedAt: original.UpdatedAt}
	if err := st.ActivateWritableUpstream(ctx, record); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetMapping(ctx, original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if got.GiteaRepoID != 57 || got.RepoName != record.NewRepoName || !got.HookInstalled {
		t.Fatalf("activated mapping=%+v", got)
	}
	journal, err := st.GetWritableUpstreamMigration(ctx, original.Npub, original.RepoID)
	if err != nil || !journal.Active || journal.OldGiteaRepoID != 21 || journal.NewGiteaRepoID != 57 {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
	if err := st.ActivateWritableUpstream(ctx, record); err == nil {
		t.Fatal("duplicate active migration succeeded")
	}
	if err := st.RollbackWritableUpstream(ctx, original.Npub, original.RepoID, 999); err == nil {
		t.Fatal("rollback accepted wrong target id")
	}
	if err := st.RollbackWritableUpstream(ctx, original.Npub, original.RepoID, 57); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetMapping(ctx, original.Npub, original.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if got.GiteaRepoID != 21 || got.RepoName != original.RepoName {
		t.Fatalf("rolled back mapping=%+v", got)
	}
	journal, err = st.GetWritableUpstreamMigration(ctx, original.Npub, original.RepoID)
	if err != nil || journal.Active {
		t.Fatalf("rolled back journal=%+v err=%v", journal, err)
	}
	if err := st.RollbackWritableUpstream(ctx, original.Npub, original.RepoID, 57); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second rollback err=%v", err)
	}
}

func TestWritableUpstreamActivationRejectsMappingDrift(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertMapping(ctx, Mapping{Npub: "npub1owner", RepoID: "demo", Pubkey: "owner", Owner: "cascadia", RepoName: "demo", GiteaRepoID: 22, CloneURL: "old", SourceEvent: "event", HookInstalled: true}); err != nil {
		t.Fatal(err)
	}
	current, getErr := st.GetMapping(ctx, "npub1owner", "demo")
	if getErr != nil {
		t.Fatal(getErr)
	}
	err = st.ActivateWritableUpstream(ctx, WritableUpstreamMigration{Npub: "npub1owner", RepoID: "demo", OldOwner: "cascadia", OldRepoName: "demo", OldGiteaRepoID: 21, OldCloneURL: "old", NewOwner: "cascadia", NewRepoName: "demo-upstream", NewGiteaRepoID: 57, NewCloneURL: "new", ExpectedMappingUpdatedAt: current.UpdatedAt})
	if err == nil {
		t.Fatal("mapping drift was accepted")
	}
	if _, getErr := st.GetWritableUpstreamMigration(ctx, "npub1owner", "demo"); !errors.Is(getErr, sql.ErrNoRows) {
		t.Fatalf("journal survived failed CAS: %v", getErr)
	}
}

func TestWritableUpstreamPreparedRevisionRejectsLaterMetadataChange(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertMapping(ctx, Mapping{Npub: "npub1owner", RepoID: "demo", Pubkey: "owner", Owner: "cascadia", RepoName: "demo", GiteaRepoID: 21, CloneURL: "old", SourceEvent: "event", HookInstalled: true}); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetMapping(ctx, "npub1owner", "demo")
	if err != nil {
		t.Fatal(err)
	}
	record := WritableUpstreamMigration{Npub: current.Npub, RepoID: current.RepoID, OldOwner: current.Owner, OldRepoName: current.RepoName, OldGiteaRepoID: current.GiteaRepoID, OldCloneURL: current.CloneURL, NewOwner: "cascadia", NewRepoName: "demo-upstream", ExpectedMappingUpdatedAt: current.UpdatedAt}
	if err := st.PrepareWritableUpstream(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE mappings SET updated_at=? WHERE npub=? AND repo_id=?`, "2099-01-01T00:00:00Z", current.Npub, current.RepoID); err != nil {
		t.Fatal(err)
	}
	record.NewGiteaRepoID, record.NewCloneURL = 57, "new"
	if err := st.ActivateWritableUpstream(ctx, record); err == nil {
		t.Fatal("activation overwrote a changed mapping revision")
	}
	journal, err := st.GetWritableUpstreamMigration(ctx, current.Npub, current.RepoID)
	if err != nil || journal.Active {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
}

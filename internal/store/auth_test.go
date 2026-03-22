package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	f, err := os.CreateTemp("", "grasp-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	st, err := Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestChallenge_CreateAndConsume(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	err := st.CreateChallenge(ctx, "id1", "state1", "https://gitea/callback", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	c, err := st.ConsumeChallenge(ctx, "id1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if c.OAuth2State != "state1" {
		t.Errorf("state mismatch: %s", c.OAuth2State)
	}
}

func TestChallenge_NotFound(t *testing.T) {
	st := openTestStore(t)
	_, err := st.ConsumeChallenge(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestChallenge_Expired(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_ = st.CreateChallenge(ctx, "expired", "s", "https://x", time.Now().Add(-1*time.Minute))
	_, err := st.ConsumeChallenge(ctx, "expired")
	if err != ErrExpired {
		t.Errorf("expected ErrExpired, got %v", err)
	}
}

func TestChallenge_AlreadyConsumed(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_ = st.CreateChallenge(ctx, "once", "s", "https://x", time.Now().Add(5*time.Minute))
	_, _ = st.ConsumeChallenge(ctx, "once")

	_, err := st.ConsumeChallenge(ctx, "once")
	if err != ErrAlreadyConsumed {
		t.Errorf("expected ErrAlreadyConsumed, got %v", err)
	}
}

func TestAuthCode_CreateAndConsume(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	err := st.CreateAuthCode(ctx, "code1", "pubkey1", "npub1xxx", "https://gitea/cb", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	ac, err := st.ConsumeAuthCode(ctx, "code1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ac.Pubkey != "pubkey1" {
		t.Errorf("pubkey mismatch: %s", ac.Pubkey)
	}
}

func TestAuthCode_ReplayRejected(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_ = st.CreateAuthCode(ctx, "code2", "pk", "npub", "https://x", time.Now().Add(time.Minute))
	_, _ = st.ConsumeAuthCode(ctx, "code2")

	_, err := st.ConsumeAuthCode(ctx, "code2")
	if err != ErrAlreadyConsumed {
		t.Errorf("expected ErrAlreadyConsumed, got %v", err)
	}
}

func TestIdentityLink_UpsertAndGet(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	link := IdentityLink{
		Pubkey:        "abcdef1234",
		Npub:          "npub1test",
		NIP05:         "user@example.com",
		GiteaUserID:   42,
		GiteaUsername: "user",
		CreatedAt:     time.Now(),
		LastLoginAt:   time.Now(),
	}

	if err := st.UpsertIdentityLink(ctx, link); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, found, err := st.GetIdentityLinkByPubkey(ctx, "abcdef1234")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !found {
		t.Fatal("expected to find link")
	}
	if got.GiteaUsername != "user" {
		t.Errorf("username mismatch: %s", got.GiteaUsername)
	}
}

func TestAccessToken_CreateGetDelete(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	tok, _ := GenerateToken()
	_ = st.CreateAccessToken(ctx, tok, "pk1", time.Now().Add(time.Hour))

	at, err := st.GetAccessToken(ctx, tok)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if at.Pubkey != "pk1" {
		t.Errorf("pubkey mismatch")
	}

	// Expired token
	expiredTok, _ := GenerateToken()
	_ = st.CreateAccessToken(ctx, expiredTok, "pk2", time.Now().Add(-time.Minute))
	_, err = st.GetAccessToken(ctx, expiredTok)
	if err != ErrExpired {
		t.Errorf("expected ErrExpired for expired token, got %v", err)
	}
}

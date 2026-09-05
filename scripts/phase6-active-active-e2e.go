//go:build ignore

// Command phase6-active-active-e2e proves shared-store invariants through two
// independent PostgresStore clients, representing separate bridge replicas.
package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sharegap/grasp-gitea/internal/store"
)

func main() {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		fail("POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, err := store.OpenPostgres(dsn)
	must("open replica A store", err)
	defer a.Close()
	b, err := store.OpenPostgres(dsn)
	must("open replica B store", err)
	defer b.Close()

	verifyReplaySingleUse(ctx, a, b)
	verifySessionHandoff(ctx, a, b)
	verifyMaintenanceLease(ctx, a, b)
	verifyIdentityConvergence(ctx, a, b)
	verifySignerConvergence(ctx, a, b)
	fmt.Println("phase6 active-active shared-store invariants: PASS")
}

func verifyReplaySingleUse(ctx context.Context, a, b store.AuthStore) {
	start := make(chan struct{})
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, st := range []store.AuthStore{a, b} {
		wg.Add(1)
		go func(st store.AuthStore) {
			defer wg.Done()
			<-start
			ok, err := st.ClaimNIP98Event(ctx, "phase6-shared-replay", "pubkey", "POST", []byte("target"), time.Now(), time.Now().Add(time.Minute))
			results <- ok
			errs <- err
		}(st)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	wins := 0
	for err := range errs {
		must("cross-node replay claim", err)
	}
	for won := range results {
		if won {
			wins++
		}
	}
	if wins != 1 {
		fail("cross-node replay winners = %d, want 1", wins)
	}
	fmt.Println("cross-node replay claim single-use: PASS")
}

func verifySessionHandoff(ctx context.Context, a, b store.AuthStore) {
	now := time.Now().UTC()
	sess := store.NIP46Session{
		SessionToken: "phase6-session", BunkerPubkey: "bunker", ClientPubkey: "client",
		State: "pending", RedirectURI: "/", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	must("create session on A", a.CreateNIP46Session(ctx, sess))
	got, err := b.GetNIP46Session(ctx, sess.SessionToken)
	must("read A session on B", err)
	if got.State != "pending" {
		fail("session state on B = %q, want pending", got.State)
	}
	must("complete session on B", b.UpdateNIP46SessionState(ctx, sess.SessionToken, "complete", "identity-pubkey", ""))
	got, err = a.GetNIP46Session(ctx, sess.SessionToken)
	must("read B session update on A", err)
	if got.State != "complete" || got.ResultPubkey != "identity-pubkey" {
		fail("session handoff did not converge: %#v", got)
	}
	fmt.Println("session handoff A -> B -> A: PASS")
}

func verifyMaintenanceLease(ctx context.Context, a, b store.AuthStore) {
	gotA, releaseA, err := a.TryMaintenanceLease(ctx)
	must("acquire maintenance lease on A", err)
	if !gotA {
		fail("replica A did not acquire uncontended maintenance lease")
	}
	defer releaseA()
	gotB, _, err := b.TryMaintenanceLease(ctx)
	must("contend maintenance lease on B", err)
	if gotB {
		fail("replica B acquired maintenance lease while A held it")
	}
	releaseA()
	releaseA = func() {}
	gotB, releaseB, err := b.TryMaintenanceLease(ctx)
	must("acquire released maintenance lease on B", err)
	if !gotB {
		fail("replica B did not acquire maintenance lease after release")
	}
	releaseB()
	fmt.Println("maintenance lease single-holder and handoff: PASS")
}

func verifyIdentityConvergence(ctx context.Context, a, b store.AuthStore) {
	now := time.Now().UTC()
	link := store.NostrIdentityLink{
		Pubkey: "phase6-identity-pubkey", Npub: "npub1phase6", GiteaUserID: 609,
		GiteaUser: "phase6-user", NIP05: "phase6@example.invalid", LastLoginAt: now,
	}
	must("write identity link on A", a.UpsertIdentityLink(ctx, link))
	byPubkey, err := b.GetIdentityLinkByPubkey(ctx, link.Pubkey)
	must("publisher/proxy/profile identity read on B", err)
	byUser, err := b.GetIdentityLinkByGiteaUserID(ctx, link.GiteaUserID)
	must("webhook actor identity read on B", err)
	page, err := b.ListIdentityLinksAfter(ctx, "phase6-identity-pubkej", 10)
	must("profile-sync identity scan on B", err)
	if byPubkey.GiteaUserID != link.GiteaUserID || byUser.Pubkey != link.Pubkey || len(page) != 1 || page[0].Pubkey != link.Pubkey {
		fail("identity link did not converge across consumer read shapes")
	}
	fmt.Println("identity-link consumer convergence: PASS")
}

func verifySignerConvergence(ctx context.Context, a, b store.AuthStore) {
	now := time.Now().UTC()
	grant := store.SignerGrant{
		Pubkey: "phase6-signer-pubkey", ClientSeckeyEnc: []byte("client-secret"),
		BunkerURIEnc: []byte("bunker-uri"), GrantedAt: now, Status: "active",
	}
	must("write signer grant on A", a.UpsertSignerGrant(ctx, grant))
	if _, err := b.GetSignerGrant(ctx, grant.Pubkey); err != nil {
		fail("read signer grant on B: %v", err)
	}
	bridgeSession := store.BridgeSignerSession{
		BunkerURI: "bunker://phase6", ClientSeckeyEnc: []byte("bridge-secret"),
		ClientPubkey: "client", SignerPubkey: "signer", CreatedAt: now,
	}
	must("write bridge signer session on A", a.UpsertBridgeSignerSession(ctx, bridgeSession))
	if _, err := b.GetBridgeSignerSession(ctx, bridgeSession.BunkerURI); err != nil {
		fail("read bridge signer session on B: %v", err)
	}
	fmt.Println("signer and publisher session convergence: PASS")
}

func must(action string, err error) {
	if err != nil {
		fail("%s: %v", action, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

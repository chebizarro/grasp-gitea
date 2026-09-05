package scim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type noopReconciler struct{}

func (noopReconciler) ReconcileHost(context.Context, string) error { return nil }

func setupSCIM(t *testing.T) (*Service, *store.SQLiteStore, string, string, string) {
	t.Helper()
	st, e := store.Open(t.TempDir() + "/scim.sqlite")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	mk := func(host, token string) {
		mt := store.ManagedTenant{Host: host, Policy: store.TenantPolicySharedRead, State: store.TenantStateActive, OrgName: "org-" + host, ProvisioningMarker: "marker-" + host, GiteaOrgID: 1, ReaderTeamID: 2, Version: 1, CreatedAt: now, UpdatedAt: now}
		if e := st.CreateManagedTenant(context.Background(), mt); e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256([]byte(token))
		if e := st.UpsertTenantSCIMToken(context.Background(), store.TenantSCIMToken{Host: host, TokenHash: h[:], TokenSuffix: token, Generation: 1, UpdatedAt: now}); e != nil {
			t.Fatal(e)
		}
	}
	mk("example.com", "token-a")
	mk("other.example", "token-b")
	pub := nostr.Generate().Public().Hex()
	if e := st.UpsertIdentityLink(context.Background(), store.NostrIdentityLink{Pubkey: pub, Npub: "npub-test", GiteaUserID: 9, GiteaUser: "alice", CreatedAt: now, UpdatedAt: now}); e != nil {
		t.Fatal(e)
	}
	return New(st, noopReconciler{}), st, "token-a", "token-b", pub
}
func request(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if e := json.NewEncoder(&b).Encode(body); e != nil {
			t.Fatal(e)
		}
	}
	r := httptest.NewRequest(method, path, &b)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func requestWithKey(t *testing.T, h http.Handler, method, path, token, key string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if e := json.NewEncoder(&b).Encode(body); e != nil {
			t.Fatal(e)
		}
	}
	r := httptest.NewRequest(method, path, &b)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func object(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), e)
	}
	return v
}

func TestOwnAuthOutboundUserDialectAndTenantAuthz(t *testing.T) {
	svc, _, tokenA, tokenB, pub := setupSCIM(t)
	h := svc.Handler()
	payload := map[string]any{"schemas": []string{userSchema}, "userName": "alice@example.com", "active": true, "name": map[string]string{"givenName": "Alice"}, "displayName": "Alice", "emails": []map[string]any{{"value": "alice@example.com", "primary": true}}, "externalId": pub}
	w := requestWithKey(t, h, http.MethodPost, "/scim/v2/Users", tokenA, "ownauth-create-1", payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	created := object(t, w)
	id := created["id"].(string)
	if created["displayName"] != "Alice" || len(created["emails"].([]any)) != 1 {
		t.Fatalf("OwnAuth attributes not preserved: %s", w.Body.String())
	}
	retry := requestWithKey(t, h, http.MethodPost, "/scim/v2/Users", tokenA, "ownauth-create-1", payload)
	if retry.Code != http.StatusOK || object(t, retry)["id"] != id {
		t.Fatalf("idempotent retry=%d %s", retry.Code, retry.Body.String())
	}
	payload["displayName"] = "Alice Updated"
	w = request(t, h, http.MethodPut, "/scim/v2/Users/"+id, tokenA, payload)
	if w.Code != http.StatusOK {
		t.Fatalf("put=%d %s", w.Code, w.Body.String())
	}
	patch := map[string]any{"schemas": []string{patchSchema}, "Operations": []map[string]any{{"op": "Replace", "path": "active", "value": false}}}
	w = request(t, h, http.MethodPatch, "/scim/v2/Users/"+id, tokenA, patch)
	if w.Code != http.StatusOK || object(t, w)["active"] != false {
		t.Fatalf("patch=%d %s", w.Code, w.Body.String())
	}
	w = request(t, h, http.MethodGet, "/scim/v2/Users/"+id, tokenB, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross tenant=%d %s", w.Code, w.Body.String())
	}
	w = request(t, h, http.MethodGet, "/scim/v2/ServiceProviderConfig", tokenA, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("discovery=%d", w.Code)
	}
}

func TestHostMismatchAndGroupPatchMembership(t *testing.T) {
	svc, _, token, _, pub := setupSCIM(t)
	h := svc.Handler()
	w := request(t, h, http.MethodPost, "/scim/v2/Users", token, map[string]any{"schemas": []string{userSchema}, "userName": "alice@other.example", "active": true, "externalId": pub})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("host mismatch=%d %s", w.Code, w.Body.String())
	}
	w = request(t, h, http.MethodPost, "/scim/v2/Users", token, map[string]any{"schemas": []string{userSchema}, "userName": "alice@example.com", "active": true, "externalId": pub})
	if w.Code != http.StatusCreated {
		t.Fatalf("user=%d %s", w.Code, w.Body.String())
	}
	uid := object(t, w)["id"].(string)
	w = request(t, h, http.MethodPost, "/scim/v2/Groups", token, map[string]any{"schemas": []string{groupSchema}, "displayName": "readers"})
	if w.Code != http.StatusCreated {
		t.Fatalf("group=%d %s", w.Code, w.Body.String())
	}
	gid := object(t, w)["id"].(string)
	add := map[string]any{"schemas": []string{patchSchema}, "Operations": []map[string]any{{"op": "Add", "path": "members", "value": []map[string]string{{"value": uid}}}}}
	w = request(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, add)
	if w.Code != http.StatusOK {
		t.Fatalf("add=%d %s", w.Code, w.Body.String())
	}
	if len(object(t, w)["members"].([]any)) != 1 {
		t.Fatal("member not added")
	}
	remove := map[string]any{"schemas": []string{patchSchema}, "Operations": []map[string]any{{"op": "Remove", "path": fmt.Sprintf("members[value eq %q]", uid)}}}
	w = request(t, h, http.MethodPatch, "/scim/v2/Groups/"+gid, token, remove)
	if w.Code != http.StatusOK {
		t.Fatalf("remove=%d %s", w.Code, w.Body.String())
	}
	if len(object(t, w)["members"].([]any)) != 0 {
		t.Fatal("member not removed")
	}
}

func TestSuspendedTenantIsRefusedImmediately(t *testing.T) {
	svc, st, token, _, _ := setupSCIM(t)
	tenant, err := st.GetManagedTenant(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	tenant.State = store.TenantStateSuspended
	tenant.Version++
	if ok, err := st.UpdateManagedTenant(context.Background(), tenant, tenant.Version-1); err != nil || !ok {
		t.Fatalf("suspend ok=%v err=%v", ok, err)
	}
	w := request(t, svc.Handler(), http.MethodGet, "/scim/v2/Users", token, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("suspended status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestUsersPaginationAndGroupBeyondFiftyMembers(t *testing.T) {
	svc, st, token, _, _ := setupSCIM(t)
	now := time.Now().UTC()
	ids := make([]string, 0, 55)
	for i := 0; i < 55; i++ {
		u := store.SCIMUser{Host: "example.com", ID: fmt.Sprintf("u-%03d", i), UserName: fmt.Sprintf("u%03d@example.com", i), ExternalID: fmt.Sprintf("%064x", i+1), Pubkey: fmt.Sprintf("%064x", i+1), Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
		if e := st.CreateSCIMUser(context.Background(), u); e != nil {
			t.Fatal(e)
		}
		ids = append(ids, u.ID)
	}
	w := request(t, svc.Handler(), http.MethodGet, "/scim/v2/Users?startIndex=51&count=50", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list=%d %s", w.Code, w.Body.String())
	}
	v := object(t, w)
	if int(v["totalResults"].(float64)) != 55 || len(v["Resources"].([]any)) != 5 {
		t.Fatalf("pagination=%s", w.Body.String())
	}
	g := store.SCIMGroup{Host: "example.com", ID: "large-group", DisplayName: "large", Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateSCIMGroup(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ReplaceSCIMGroupMembers(context.Background(), g.Host, g.ID, ids, 1, now); err != nil || !ok {
		t.Fatalf("members ok=%v err=%v", ok, err)
	}
	w = request(t, svc.Handler(), http.MethodGet, "/scim/v2/Groups/"+g.ID, token, nil)
	if w.Code != http.StatusOK || len(object(t, w)["members"].([]any)) != 55 {
		t.Fatalf("large group=%d %s", w.Code, w.Body.String())
	}
}

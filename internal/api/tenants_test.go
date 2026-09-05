package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
)

type fakeTenantOperator struct{ killed bool }

func (f *fakeTenantOperator) Get(context.Context, string) (store.ManagedTenant, error) {
	return store.ManagedTenant{Host: "example.com"}, nil
}
func (f *fakeTenantOperator) Approve(_ context.Context, h, p string) (store.ManagedTenant, error) {
	return store.ManagedTenant{Host: h, Policy: p, State: store.TenantStatePending}, nil
}
func (f *fakeTenantOperator) Create(context.Context, string) (store.ManagedTenant, error) {
	return store.ManagedTenant{Host: "example.com", State: store.TenantStateActive}, nil
}
func (f *fakeTenantOperator) Suspend(context.Context, string) (store.ManagedTenant, error) {
	return store.ManagedTenant{}, nil
}
func (f *fakeTenantOperator) Resume(context.Context, string) (store.ManagedTenant, error) {
	return store.ManagedTenant{}, nil
}
func (f *fakeTenantOperator) RotateSCIMToken(_ context.Context, h string) (store.ManagedTenant, string, error) {
	return store.ManagedTenant{Host: h, State: store.TenantStateActive}, "one-time-token", nil
}
func (f *fakeTenantOperator) Kill(context.Context, string) (store.ManagedTenant, error) {
	f.killed = true
	return store.ManagedTenant{State: store.TenantStateKilled}, nil
}

func TestTenantAdminRequiresTokenAndKillIsPostOnly(t *testing.T) {
	s := New(config.Config{AdminAPIToken: "secret"}, nil, nil, nil, nil)
	op := &fakeTenantOperator{}
	s.SetTenantOperator(op)
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/example.com/kill", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || op.killed {
		t.Fatalf("unauthenticated kill status=%d killed=%v", w.Code, op.killed)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/tenants/example.com/kill", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed || op.killed {
		t.Fatalf("GET kill status=%d killed=%v", w.Code, op.killed)
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/tenants/example.com/kill", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !op.killed {
		t.Fatalf("authorized kill status=%d killed=%v", w.Code, op.killed)
	}
}

func TestTenantAdminRotatesSCIMToken(t *testing.T) {
	s := New(config.Config{AdminAPIToken: "secret"}, nil, nil, nil, nil)
	s.SetTenantOperator(&fakeTenantOperator{})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/example.com/scim-token", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "one-time-token") {
		t.Fatalf("rotate status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("secret response cache headers=%v", w.Header())
	}
}

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/tenant"
)

type fakeTenantOperator struct{ killed bool }

func (f *fakeTenantOperator) Get(context.Context, string) (store.ManagedTenant, error) {
	return store.ManagedTenant{Host: "example.com"}, nil
}
func (f *fakeTenantOperator) Approve(_ context.Context, h, p string, placement *bool) (store.ManagedTenant, error) {
	enabled := placement != nil && *placement
	return store.ManagedTenant{Host: h, Policy: p, PlacementEnabled: enabled, State: store.TenantStatePending}, nil
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
func (f *fakeTenantOperator) GetPackagePolicy(context.Context, string) (store.TenantPackagePolicy, error) {
	return store.TenantPackagePolicy{Host: "example.com", AllocationMode: store.TenantPackageAllocationExplicit, Version: 1}, nil
}
func (f *fakeTenantOperator) UpdatePackagePolicy(_ context.Context, h string, p tenant.PackagePolicyPatch) (store.TenantPackagePolicy, error) {
	return store.TenantPackagePolicy{Host: h, Enabled: p.Enabled != nil && *p.Enabled, AllowedFamilies: *p.AllowedFamilies, AllocationMode: *p.AllocationMode, Version: p.ExpectedVersion + 1}, nil
}
func (f *fakeTenantOperator) CreatePackageAllocation(_ context.Context, h string, r tenant.PackageAllocationRequest) (store.TenantPackageAllocation, error) {
	return store.TenantPackageAllocation{Host: h, Family: r.Family, Name: r.Name, TargetType: r.TargetType, TargetID: r.TargetID, Visibility: r.Visibility, Version: 1}, nil
}
func (f *fakeTenantOperator) ListPackageAllocations(context.Context, string, string) ([]store.TenantPackageAllocation, error) {
	return []store.TenantPackageAllocation{{Name: "widget"}}, nil
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

func TestTenantAdminSetsExplicitPlacementPolicy(t *testing.T) {
	s := New(config.Config{AdminAPIToken: "secret"}, nil, nil, nil, nil)
	s.SetTenantOperator(&fakeTenantOperator{})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/example.com/approve", strings.NewReader(`{"policy":"directory-only","placement_enabled":true}`))
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"placement_enabled":true`) {
		t.Fatalf("approve status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTenantPackagePolicyAndAllocationAdmin(t *testing.T) {
	s := New(config.Config{AdminAPIToken: "secret"}, nil, nil, nil, nil)
	s.SetTenantOperator(&fakeTenantOperator{})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := request(http.MethodPost, "/admin/tenants/example.com/package-policy", `{"expected_version":1,"enabled":true,"allowed_families":["docker","npm","generic"],"allocation_mode":"explicit"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("policy status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(http.MethodPost, "/admin/tenants/example.com/package-allocations", `{"family":"docker","name":"app","target_type":"pubkey","target_id":"pub","visibility":"private"}`)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"name":"app"`) {
		t.Fatalf("allocation status=%d body=%s", w.Code, w.Body.String())
	}
	w = request(http.MethodGet, "/admin/tenants/example.com/package-allocations?family=docker", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "widget") {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
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

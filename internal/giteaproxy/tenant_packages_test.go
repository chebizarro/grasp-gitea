package giteaproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/tenant"
)

type stubPackageAuthorizer struct {
	err         error
	decision    tenant.PackageAuthorizationDecision
	requests    []tenant.PackageAuthorizationRequest
	completions []bool
}

func (s *stubPackageAuthorizer) AuthorizePackageRequest(_ context.Context, r tenant.PackageAuthorizationRequest) (tenant.PackageAuthorizationDecision, error) {
	s.requests = append(s.requests, r)
	if !s.decision.Managed {
		s.decision.Managed = true
	}
	return s.decision, s.err
}
func (s *stubPackageAuthorizer) CompletePackageRequest(_ context.Context, _ tenant.PackageAuthorizationDecision, success bool) error {
	s.completions = append(s.completions, success)
	return nil
}

func packagePrincipal() auth.TokenPrincipal {
	return auth.TokenPrincipal{TokenID: "tok", Pubkey: "pub", GiteaUserID: 9, GiteaUser: "alice", Scopes: []string{auth.ScopePackagesRead, auth.ScopePackagesWrite}}
}

func TestDockerTenantScopeCheckedBeforePATExchange(t *testing.T) {
	tokens := &stubAuthenticator{enabled: true, principal: packagePrincipal(), patLogin: "alice", patSecret: "pat"}
	env := newProxyEnv(t, Config{}, tokens, nil)
	authorizer := &stubPackageAuthorizer{err: tenant.ErrPackageDenied}
	env.proxy.WithTenantPackageAuthorizer(authorizer)
	r := httptest.NewRequest(http.MethodGet, "/v2/token?scope=repository:grasp-t/example/image:pull,push", nil)
	r.Header.Set("Authorization", basicHeader("alice", testBridgeToken))
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if tokens.patCalls != 0 {
		t.Fatalf("PAT exchange called %d times", tokens.patCalls)
	}
	if env.seen.snapshot().hit {
		t.Fatal("denied token exchange reached Gitea")
	}
	if len(authorizer.requests) != 1 || len(authorizer.requests[0].Coordinates) != 1 || authorizer.requests[0].Coordinates[0].Name != "example/image" || !authorizer.requests[0].Coordinates[0].Write {
		t.Fatalf("request=%+v", authorizer.requests)
	}
}

func TestDockerRejectsEveryNonRepositoryScopeBeforePAT(t *testing.T) {
	for _, scope := range []string{"registry:catalog:*", "admin:anything:pull", "artifact:o/img:pull"} {
		t.Run(scope, func(t *testing.T) {
			tokens := &stubAuthenticator{enabled: true, principal: packagePrincipal(), patLogin: "alice", patSecret: "pat"}
			env := newProxyEnv(t, Config{}, tokens, nil)
			r := httptest.NewRequest(http.MethodGet, "/v2/token?scope="+scope, nil)
			r.Header.Set("Authorization", basicHeader("alice", testBridgeToken))
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tokens.patCalls != 0 || env.seen.snapshot().hit {
				t.Fatalf("scope forwarded patCalls=%d hit=%v", tokens.patCalls, env.seen.snapshot().hit)
			}
			ordinary := httptest.NewRequest(http.MethodGet, "/v2/token?scope="+scope, nil)
			ordinary.Header.Set("Authorization", basicHeader("alice", "ordinary-gitea-password"))
			ordinaryW := httptest.NewRecorder()
			env.proxy.ServeHTTP(ordinaryW, ordinary)
			if ordinaryW.Code != http.StatusBadRequest || env.seen.snapshot().hit {
				t.Fatalf("ordinary credential scope forwarded status=%d hit=%v", ordinaryW.Code, env.seen.snapshot().hit)
			}
		})
	}
}

func TestNPMAndGenericTenantPathsAreAuthorized(t *testing.T) {
	for _, tc := range []struct {
		name, path, want string
		method           string
	}{{"npm", "/api/packages/grasp-t/npm/@scope/pkg", "@scope/pkg", http.MethodPut}, {"generic", "/api/packages/grasp-t/generic/artifact/1.0/file.tgz", "artifact", http.MethodGet}} {
		t.Run(tc.name, func(t *testing.T) {
			tokens := &stubAuthenticator{enabled: true, principal: packagePrincipal(), patLogin: "alice", patSecret: "pat"}
			env := newProxyEnv(t, Config{}, tokens, nil)
			authorizer := &stubPackageAuthorizer{}
			env.proxy.WithTenantPackageAuthorizer(authorizer)
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Authorization", "Bearer "+testBridgeToken)
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if len(authorizer.requests) != 1 || authorizer.requests[0].Coordinates[0].Name != tc.want {
				t.Fatalf("requests=%+v", authorizer.requests)
			}
		})
	}
}

func TestOpenAllocationCompletionFollowsUpstreamResult(t *testing.T) {
	for _, tc := range []struct {
		name         string
		closeBackend bool
		want         bool
	}{{"success", false, true}, {"failure", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			tokens := &stubAuthenticator{enabled: true, principal: packagePrincipal(), patLogin: "alice", patSecret: "pat"}
			env := newProxyEnv(t, Config{}, tokens, nil)
			authorizer := &stubPackageAuthorizer{decision: tenant.PackageAuthorizationDecision{Managed: true, Reservations: []tenant.PackageReservation{{Host: "h", Family: "npm", Name: "pkg", ID: "r", FinalizeOnSuccess: true}}}}
			env.proxy.WithTenantPackageAuthorizer(authorizer)
			if tc.closeBackend {
				env.backend.Close()
			}
			r := httptest.NewRequest(http.MethodPut, "/api/packages/owner/npm/pkg", nil)
			r.Header.Set("Authorization", "Bearer "+testBridgeToken)
			w := httptest.NewRecorder()
			env.proxy.ServeHTTP(w, r)
			if len(authorizer.completions) != 1 || authorizer.completions[0] != tc.want {
				t.Fatalf("completions=%v status=%d", authorizer.completions, w.Code)
			}
		})
	}
}

func TestPrivateTenantDownloadRequiresBridgeIdentity(t *testing.T) {
	env := newProxyEnv(t, Config{}, nil, nil)
	authorizer := &stubPackageAuthorizer{err: tenant.ErrPackageAuthRequired}
	env.proxy.WithTenantPackageAuthorizer(authorizer)
	r := httptest.NewRequest(http.MethodGet, "/api/packages/grasp-t/generic/artifact/1/file", nil)
	w := httptest.NewRecorder()
	env.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
	if env.seen.snapshot().hit {
		t.Fatal("private download reached Gitea")
	}
}

var _ = errors.Is

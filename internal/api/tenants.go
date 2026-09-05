package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/provisioner"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/tenant"
)

type SCIMTokenRotator interface {
	RotateSCIMToken(context.Context, string) (store.ManagedTenant, string, error)
}

type TenantPackageOperator interface {
	GetPackagePolicy(context.Context, string) (store.TenantPackagePolicy, error)
	UpdatePackagePolicy(context.Context, string, tenant.PackagePolicyPatch) (store.TenantPackagePolicy, error)
	CreatePackageAllocation(context.Context, string, tenant.PackageAllocationRequest) (store.TenantPackageAllocation, error)
	ListPackageAllocations(context.Context, string, string) ([]store.TenantPackageAllocation, error)
}

type TenantOperator interface {
	Get(context.Context, string) (store.ManagedTenant, error)
	Approve(context.Context, string, string, *bool) (store.ManagedTenant, error)
	Create(context.Context, string) (store.ManagedTenant, error)
	Suspend(context.Context, string) (store.ManagedTenant, error)
	Resume(context.Context, string) (store.ManagedTenant, error)
	Kill(context.Context, string) (store.ManagedTenant, error)
}

func (s *Server) tenantAction(w http.ResponseWriter, r *http.Request) {
	if s.tenantOperator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant service is not configured"})
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/tenants/"), "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown tenant action"})
		return
	}
	host := parts[0]
	action := "get"
	if len(parts) == 2 {
		action = parts[1]
	}
	if action != "get" && action != "package-policy" && action != "package-allocations" && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var out store.ManagedTenant
	var plaintextToken string
	var err error
	switch action {
	case "get":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		out, err = s.tenantOperator.Get(r.Context(), host)
	case "approve":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var body struct {
			Policy           string `json:"policy"`
			PlacementEnabled *bool  `json:"placement_enabled"`
		}
		if r.Body != nil {
			dec := json.NewDecoder(r.Body)
			if e := dec.Decode(&body); e != nil && e.Error() != "EOF" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
		}
		out, err = s.tenantOperator.Approve(r.Context(), host, body.Policy, body.PlacementEnabled)
	case "create":
		out, err = s.tenantOperator.Create(r.Context(), host)
	case "suspend":
		out, err = s.tenantOperator.Suspend(r.Context(), host)
	case "resume":
		out, err = s.tenantOperator.Resume(r.Context(), host)
	case "kill":
		out, err = s.tenantOperator.Kill(r.Context(), host)
	case "package-policy":
		packages, ok := s.tenantOperator.(TenantPackageOperator)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant package service is not configured"})
			return
		}
		if r.Method == http.MethodGet {
			policy, e := packages.GetPackagePolicy(r.Context(), host)
			if e != nil {
				err = e
				break
			}
			writeJSON(w, http.StatusOK, policy)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var body struct {
			ExpectedVersion int64     `json:"expected_version"`
			Enabled         *bool     `json:"enabled"`
			AllowedFamilies *[]string `json:"allowed_families"`
			AllocationMode  *string   `json:"allocation_mode"`
		}
		if r.Body == nil || json.NewDecoder(r.Body).Decode(&body) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		policy, e := packages.UpdatePackagePolicy(r.Context(), host, tenant.PackagePolicyPatch{ExpectedVersion: body.ExpectedVersion, Enabled: body.Enabled, AllowedFamilies: body.AllowedFamilies, AllocationMode: body.AllocationMode})
		if e != nil {
			err = e
			break
		}
		writeJSON(w, http.StatusOK, policy)
		return
	case "package-allocations":
		packages, ok := s.tenantOperator.(TenantPackageOperator)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant package service is not configured"})
			return
		}
		if r.Method == http.MethodGet {
			allocations, e := packages.ListPackageAllocations(r.Context(), host, r.URL.Query().Get("family"))
			if e != nil {
				err = e
				break
			}
			writeJSON(w, http.StatusOK, allocations)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var body tenant.PackageAllocationRequest
		if r.Body == nil || json.NewDecoder(r.Body).Decode(&body) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		allocation, e := packages.CreatePackageAllocation(r.Context(), host, body)
		if e != nil {
			err = e
			break
		}
		writeJSON(w, http.StatusCreated, allocation)
		return
	case "scim-token":
		rotator, ok := s.tenantOperator.(SCIMTokenRotator)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "SCIM token service is not configured"})
			return
		}
		out, plaintextToken, err = rotator.RotateSCIMToken(r.Context(), host)
	case "migrate":
		if s.provisioner == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "repository migration service is not configured"})
			return
		}
		var body struct {
			Npub   string `json:"npub"`
			RepoID string `json:"repo_id"`
		}
		if r.Body == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		dec := json.NewDecoder(r.Body)
		if dec.Decode(&body) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		mapping, migrateErr := s.provisioner.MigrateExisting(r.Context(), host, body.Npub, body.RepoID)
		if migrateErr != nil {
			status := http.StatusInternalServerError
			if errors.Is(migrateErr, provisioner.ErrMigrationPreflight) {
				status = http.StatusConflict
			}
			writeJSON(w, status, map[string]string{"error": migrateErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mapping)
		return
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown tenant action"})
		return
	}
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, tenant.ErrNotFound) {
			status = http.StatusNotFound
		} else if errors.Is(err, tenant.ErrConflict) {
			status = http.StatusConflict
		} else if errors.Is(err, tenant.ErrWorkerRequired) {
			status = http.StatusServiceUnavailable
		} else if strings.Contains(err.Error(), "invalid") {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if plaintextToken != "" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusOK, map[string]any{"tenant": out, "token": plaintextToken})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

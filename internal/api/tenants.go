package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/tenant"
)

type TenantOperator interface {
	Get(context.Context, string) (store.ManagedTenant, error)
	Approve(context.Context, string, string) (store.ManagedTenant, error)
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
	if action != "get" && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var out store.ManagedTenant
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
			Policy string `json:"policy"`
		}
		if r.Body != nil {
			dec := json.NewDecoder(r.Body)
			if e := dec.Decode(&body); e != nil && e.Error() != "EOF" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
				return
			}
		}
		out, err = s.tenantOperator.Approve(r.Context(), host, body.Policy)
	case "create":
		out, err = s.tenantOperator.Create(r.Context(), host)
	case "suspend":
		out, err = s.tenantOperator.Suspend(r.Context(), host)
	case "resume":
		out, err = s.tenantOperator.Resume(r.Context(), host)
	case "kill":
		out, err = s.tenantOperator.Kill(r.Context(), host)
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
	writeJSON(w, http.StatusOK, out)
}

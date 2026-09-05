package scim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/tenant"
)

const (
	userSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	listSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
)

type Reconciler interface {
	ReconcileHost(context.Context, string) error
}
type Service struct {
	store      store.AuthStore
	reconciler Reconciler
	now        func() time.Time
}

func New(st store.AuthStore, r Reconciler) *Service {
	return &Service{store: st, reconciler: r, now: time.Now}
}

type userInput struct {
	Schemas     []string          `json:"schemas,omitempty"`
	UserName    string            `json:"userName"`
	ExternalID  string            `json:"externalId"`
	Active      *bool             `json:"active,omitempty"`
	Name        map[string]string `json:"name,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	Emails      []map[string]any  `json:"emails,omitempty"`
}
type memberInput struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}
type groupInput struct {
	Schemas     []string      `json:"schemas,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []memberInput `json:"members,omitempty"`
}
type patchInput struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

type authed struct{ tenant store.ManagedTenant }

func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serve) }
func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	a, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/scim/v2"), "/")
	switch {
	case path == "ServiceProviderConfig" && r.Method == http.MethodGet:
		s.discovery(w, "ServiceProviderConfig")
	case path == "Schemas" && r.Method == http.MethodGet:
		s.discovery(w, "Schemas")
	case path == "ResourceTypes" && r.Method == http.MethodGet:
		s.discovery(w, "ResourceTypes")
	case path == "Users":
		s.users(w, r, a)
	case strings.HasPrefix(path, "Users/"):
		s.user(w, r, a, strings.TrimPrefix(path, "Users/"))
	case path == "Groups":
		s.groups(w, r, a)
	case strings.HasPrefix(path, "Groups/"):
		s.group(w, r, a, strings.TrimPrefix(path, "Groups/"))
	default:
		scimError(w, http.StatusNotFound, "resource not found")
	}
}
func (s *Service) authenticate(w http.ResponseWriter, r *http.Request) (authed, bool) {
	a := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(a, "Bearer ") {
		scimError(w, http.StatusUnauthorized, "bearer authorization required")
		return authed{}, false
	}
	plain := strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
	if plain == "" {
		scimError(w, http.StatusUnauthorized, "bearer authorization required")
		return authed{}, false
	}
	h := sha256.Sum256([]byte(plain))
	tok, e := s.store.GetTenantSCIMTokenByHash(r.Context(), h[:])
	if e != nil || subtle.ConstantTimeCompare(tok.TokenHash, h[:]) != 1 {
		scimError(w, http.StatusForbidden, "invalid tenant token")
		return authed{}, false
	}
	t, e := s.store.GetManagedTenant(r.Context(), tok.Host)
	if e != nil {
		scimError(w, http.StatusForbidden, "invalid tenant token")
		return authed{}, false
	}
	if t.State == store.TenantStateSuspended || t.State == store.TenantStateKilled {
		scimError(w, http.StatusForbidden, "tenant is not active")
		return authed{}, false
	}
	if t.State != store.TenantStateActive {
		scimError(w, http.StatusConflict, "tenant is not provisioned")
		return authed{}, false
	}
	return authed{t}, true
}
func scimError(w http.ResponseWriter, status int, detail string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{errorSchema}, "status": strconv.Itoa(status), "detail": detail})
}
func write(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	if e := d.Decode(v); e != nil {
		scimError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		scimError(w, http.StatusBadRequest, "request must contain one JSON value")
		return false
	}
	return true
}
func id() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func requestID(host, key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return id()
	}
	h := sha256.Sum256([]byte(host + "\x00" + key))
	return hex.EncodeToString(h[:16]), nil
}
func parsePubkey(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) == 64 {
		p, e := nostr.PubKeyFromHex(strings.ToLower(v))
		if e != nil {
			return "", e
		}
		return p.Hex(), nil
	}
	typ, x, e := nip19.Decode(v)
	if e != nil || typ != "npub" {
		return "", fmt.Errorf("externalId must be an npub or 64-character hex pubkey")
	}
	p, ok := x.(nostr.PubKey)
	if !ok {
		return "", fmt.Errorf("invalid npub")
	}
	return p.Hex(), nil
}
func validateUser(t store.ManagedTenant, in userInput) (string, error) {
	parts := strings.Split(in.UserName, "@")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "", fmt.Errorf("userName must be a NIP-05 local@host identifier")
	}
	h, e := tenant.CanonicalHost(parts[1])
	if e != nil || h != t.Host {
		return "", fmt.Errorf("userName host does not match tenant canonical host")
	}
	return parsePubkey(in.ExternalID)
}
func (s *Service) changed(ctx context.Context, t store.ManagedTenant, fn func(context.Context, *store.ManagedTenant) error) error {
	e := s.store.WithTenantLock(ctx, t.Host, func(ctx context.Context) error {
		fresh, e := s.store.GetManagedTenant(ctx, t.Host)
		if e != nil {
			return e
		}
		if fresh.State != store.TenantStateActive {
			return tenant.ErrConflict
		}
		if e = fn(ctx, &fresh); e != nil {
			return e
		}
		return nil
	})
	if e == nil && s.reconciler != nil {
		e = s.reconciler.ReconcileHost(ctx, t.Host)
	}
	return e
}

func userResource(u store.SCIMUser) map[string]any {
	out := map[string]any{"schemas": []string{userSchema}, "id": u.ID, "userName": u.UserName, "externalId": u.ExternalID, "active": u.Active, "meta": map[string]any{"resourceType": "User", "created": u.CreatedAt, "lastModified": u.UpdatedAt, "version": fmt.Sprintf("W/\"%d\"", u.Version), "location": "/scim/v2/Users/" + u.ID}}
	var profile map[string]any
	if json.Unmarshal([]byte(u.ProfileJSON), &profile) == nil {
		for k, v := range profile {
			out[k] = v
		}
	}
	return out
}
func encodeProfile(in userInput) string {
	b, _ := json.Marshal(map[string]any{"name": in.Name, "displayName": in.DisplayName, "emails": in.Emails})
	return string(b)
}
func groupResource(g store.SCIMGroup, m []string) map[string]any {
	ms := make([]map[string]string, 0, len(m))
	for _, id := range m {
		ms = append(ms, map[string]string{"value": id, "$ref": "/scim/v2/Users/" + id})
	}
	return map[string]any{"schemas": []string{groupSchema}, "id": g.ID, "displayName": g.DisplayName, "members": ms, "meta": map[string]any{"resourceType": "Group", "created": g.CreatedAt, "lastModified": g.UpdatedAt, "version": fmt.Sprintf("W/\"%d\"", g.Version), "location": "/scim/v2/Groups/" + g.ID}}
}
func pagination(r *http.Request) (int, int) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count <= 0 {
		count = 100
	}
	if count > 200 {
		count = 200
	}
	return start, count
}
func listResponse(resources []any, total, start int) map[string]any {
	return map[string]any{"schemas": []string{listSchema}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources}
}

func (s *Service) users(w http.ResponseWriter, r *http.Request, a authed) {
	switch r.Method {
	case http.MethodGet:
		start, count := pagination(r)
		us, total, e := s.store.ListSCIMUsers(r.Context(), a.tenant.Host, start-1, count)
		if e != nil {
			scimError(w, 500, e.Error())
			return
		}
		rs := make([]any, len(us))
		for i, u := range us {
			rs[i] = userResource(u)
		}
		write(w, 200, listResponse(rs, total, start))
	case http.MethodPost:
		var in userInput
		if !decode(w, r, &in) {
			return
		}
		pub, e := validateUser(a.tenant, in)
		if e != nil {
			scimError(w, 400, e.Error())
			return
		}
		if _, e = s.store.GetIdentityLinkByPubkey(r.Context(), pub); e != nil {
			scimError(w, 400, "externalId is not linked to a Gitea identity")
			return
		}
		rid, e := requestID(a.tenant.Host, r.Header.Get("Idempotency-Key"))
		if e != nil {
			scimError(w, 500, e.Error())
			return
		}
		active := true
		if in.Active != nil {
			active = *in.Active
		}
		now := s.now().UTC()
		u := store.SCIMUser{Host: a.tenant.Host, ID: rid, UserName: strings.ToLower(strings.TrimSpace(in.UserName)), ExternalID: strings.TrimSpace(in.ExternalID), Pubkey: pub, ProfileJSON: encodeProfile(in), Active: active, Version: 1, CreatedAt: now, UpdatedAt: now}
		e = s.changed(r.Context(), a.tenant, func(ctx context.Context, t *store.ManagedTenant) error {
			ok, e := s.store.ApplySCIMUserAndAdvanceTenant(ctx, u, 0, t.Version, true)
			if e == nil && !ok {
				e = tenant.ErrConflict
			}
			return e
		})
		if e != nil {
			existing, getErr := s.store.GetSCIMUser(r.Context(), a.tenant.Host, rid)
			if getErr == nil && existing.UserName == u.UserName && existing.ExternalID == u.ExternalID && existing.Pubkey == u.Pubkey && existing.Active == u.Active && existing.ProfileJSON == u.ProfileJSON {
				write(w, http.StatusOK, userResource(existing))
				return
			}
			scimError(w, 409, e.Error())
			return
		}
		write(w, 201, userResource(u))
	default:
		w.Header().Set("Allow", "GET, POST")
		scimError(w, 405, "method not allowed")
	}
}
func (s *Service) scopedUser(ctx context.Context, host, id string) (store.SCIMUser, error) {
	u, e := s.store.GetSCIMUser(ctx, host, id)
	if errors.Is(e, sql.ErrNoRows) {
		if other, x := s.store.GetSCIMUserHost(ctx, id); x == nil && other != host {
			return u, errCrossTenant
		}
	}
	return u, e
}

var errCrossTenant = errors.New("resource belongs to another tenant")

func itemError(w http.ResponseWriter, e error) {
	if errors.Is(e, errCrossTenant) {
		scimError(w, 403, e.Error())
	} else if errors.Is(e, sql.ErrNoRows) {
		scimError(w, 404, "resource not found")
	} else {
		scimError(w, 500, e.Error())
	}
}
func (s *Service) user(w http.ResponseWriter, r *http.Request, a authed, id string) {
	u, e := s.scopedUser(r.Context(), a.tenant.Host, id)
	if e != nil {
		itemError(w, e)
		return
	}
	switch r.Method {
	case http.MethodGet:
		write(w, 200, userResource(u))
	case http.MethodPut:
		var in userInput
		if !decode(w, r, &in) {
			return
		}
		pub, e := validateUser(a.tenant, in)
		if e != nil {
			scimError(w, 400, e.Error())
			return
		}
		if _, e = s.store.GetIdentityLinkByPubkey(r.Context(), pub); e != nil {
			scimError(w, 400, "externalId is not linked to a Gitea identity")
			return
		}
		active := false
		if in.Active != nil {
			active = *in.Active
		}
		u.UserName = strings.ToLower(strings.TrimSpace(in.UserName))
		u.ExternalID = strings.TrimSpace(in.ExternalID)
		u.Pubkey = pub
		u.ProfileJSON = encodeProfile(in)
		u.Active = active
		e = s.updateUser(r.Context(), a.tenant, &u)
		if e != nil {
			scimError(w, 409, e.Error())
			return
		}
		write(w, 200, userResource(u))
	case http.MethodPatch:
		var p patchInput
		if !decode(w, r, &p) {
			return
		}
		if len(p.Operations) == 0 {
			scimError(w, 400, "PATCH Operations required")
			return
		}
		for _, op := range p.Operations {
			if !strings.EqualFold(op.Op, "replace") || !strings.EqualFold(strings.TrimSpace(op.Path), "active") {
				scimError(w, 400, "unsupported User PATCH operation")
				return
			}
			var v bool
			if e = json.Unmarshal(op.Value, &v); e != nil {
				scimError(w, 400, "active must be boolean")
				return
			}
			u.Active = v
		}
		if e = s.updateUser(r.Context(), a.tenant, &u); e != nil {
			scimError(w, 409, e.Error())
			return
		}
		write(w, 200, userResource(u))
	case http.MethodDelete:
		u.Active = false
		if e = s.updateUser(r.Context(), a.tenant, &u); e != nil {
			scimError(w, 409, e.Error())
			return
		}
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		scimError(w, 405, "method not allowed")
	}
}
func (s *Service) updateUser(ctx context.Context, t store.ManagedTenant, u *store.SCIMUser) error {
	old := u.Version
	u.Version++
	u.UpdatedAt = s.now().UTC()
	return s.changed(ctx, t, func(ctx context.Context, fresh *store.ManagedTenant) error {
		ok, e := s.store.ApplySCIMUserAndAdvanceTenant(ctx, *u, old, fresh.Version, false)
		if e == nil && !ok {
			e = tenant.ErrConflict
		}
		return e
	})
}

func (s *Service) groups(w http.ResponseWriter, r *http.Request, a authed) {
	switch r.Method {
	case http.MethodGet:
		start, count := pagination(r)
		gs, total, e := s.store.ListSCIMGroups(r.Context(), a.tenant.Host, start-1, count)
		if e != nil {
			scimError(w, 500, e.Error())
			return
		}
		rs := make([]any, len(gs))
		for i, g := range gs {
			m, e := s.store.ListSCIMGroupMembers(r.Context(), a.tenant.Host, g.ID)
			if e != nil {
				scimError(w, 500, e.Error())
				return
			}
			rs[i] = groupResource(g, m)
		}
		write(w, 200, listResponse(rs, total, start))
	case http.MethodPost:
		var in groupInput
		if !decode(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.DisplayName) == "" {
			scimError(w, 400, "displayName is required")
			return
		}
		ids, e := s.validateMembers(r.Context(), a.tenant.Host, in.Members)
		if e != nil {
			scimError(w, 400, e.Error())
			return
		}
		rid, e := requestID(a.tenant.Host, r.Header.Get("Idempotency-Key"))
		if e != nil {
			scimError(w, 500, e.Error())
			return
		}
		now := s.now().UTC()
		g := store.SCIMGroup{Host: a.tenant.Host, ID: rid, DisplayName: strings.TrimSpace(in.DisplayName), Active: true, Version: 1, CreatedAt: now, UpdatedAt: now}
		e = s.changed(r.Context(), a.tenant, func(ctx context.Context, t *store.ManagedTenant) error {
			ok, e := s.store.ApplySCIMGroupAndAdvanceTenant(ctx, g, ids, 0, t.Version, true)
			if e == nil && !ok {
				e = tenant.ErrConflict
			}
			return e
		})
		if e != nil {
			existing, getErr := s.store.GetSCIMGroup(r.Context(), a.tenant.Host, rid)
			if getErr == nil && existing.DisplayName == g.DisplayName {
				existingMembers, membersErr := s.store.ListSCIMGroupMembers(r.Context(), a.tenant.Host, rid)
				if membersErr == nil && sameMembers(existingMembers, ids) {
					write(w, http.StatusOK, groupResource(existing, existingMembers))
					return
				}
			}
			scimError(w, 409, e.Error())
			return
		}
		write(w, 201, groupResource(g, ids))
	default:
		w.Header().Set("Allow", "GET, POST")
		scimError(w, 405, "method not allowed")
	}
}
func (s *Service) scopedGroup(ctx context.Context, host, id string) (store.SCIMGroup, error) {
	g, e := s.store.GetSCIMGroup(ctx, host, id)
	if errors.Is(e, sql.ErrNoRows) {
		if other, x := s.store.GetSCIMGroupHost(ctx, id); x == nil && other != host {
			return g, errCrossTenant
		}
	}
	return g, e
}
func (s *Service) validateMembers(ctx context.Context, host string, in []memberInput) ([]string, error) {
	seen := map[string]bool{}
	ids := make([]string, 0, len(in))
	for _, m := range in {
		id := strings.TrimSpace(m.Value)
		if id == "" {
			return nil, fmt.Errorf("member value is required")
		}
		if _, e := s.store.GetSCIMUser(ctx, host, id); e != nil {
			return nil, fmt.Errorf("member %s is not a tenant user", id)
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}
func (s *Service) group(w http.ResponseWriter, r *http.Request, a authed, id string) {
	g, e := s.scopedGroup(r.Context(), a.tenant.Host, id)
	if e != nil {
		itemError(w, e)
		return
	}
	members, e := s.store.ListSCIMGroupMembers(r.Context(), g.Host, g.ID)
	if e != nil {
		itemError(w, e)
		return
	}
	switch r.Method {
	case http.MethodGet:
		write(w, 200, groupResource(g, members))
	case http.MethodPut:
		var in groupInput
		if !decode(w, r, &in) {
			return
		}
		if strings.TrimSpace(in.DisplayName) == "" {
			scimError(w, 400, "displayName is required")
			return
		}
		ids, e := s.validateMembers(r.Context(), g.Host, in.Members)
		if e != nil {
			scimError(w, 400, e.Error())
			return
		}
		g.DisplayName = strings.TrimSpace(in.DisplayName)
		if e = s.replaceGroup(r.Context(), a.tenant, &g, ids); e != nil {
			scimError(w, 409, e.Error())
			return
		}
		write(w, 200, groupResource(g, ids))
	case http.MethodPatch:
		var p patchInput
		if !decode(w, r, &p) {
			return
		}
		ids, e := s.patchMembers(r.Context(), g.Host, members, p)
		if e != nil {
			scimError(w, 400, e.Error())
			return
		}
		if e = s.replaceGroup(r.Context(), a.tenant, &g, ids); e != nil {
			scimError(w, 409, e.Error())
			return
		}
		write(w, 200, groupResource(g, ids))
	case http.MethodDelete:
		g.Active = false
		if e = s.replaceGroup(r.Context(), a.tenant, &g, nil); e != nil {
			scimError(w, 409, e.Error())
			return
		}
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE")
		scimError(w, 405, "method not allowed")
	}
}
func (s *Service) replaceGroup(ctx context.Context, t store.ManagedTenant, g *store.SCIMGroup, ids []string) error {
	old := g.Version
	g.Version++
	g.UpdatedAt = s.now().UTC()
	return s.changed(ctx, t, func(ctx context.Context, fresh *store.ManagedTenant) error {
		ok, e := s.store.ApplySCIMGroupAndAdvanceTenant(ctx, *g, ids, old, fresh.Version, false)
		if e == nil && !ok {
			e = tenant.ErrConflict
		}
		return e
	})
}
func (s *Service) patchMembers(ctx context.Context, host string, current []string, p patchInput) ([]string, error) {
	set := map[string]bool{}
	for _, id := range current {
		set[id] = true
	}
	for _, op := range p.Operations {
		o := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)
		var vals []memberInput
		if len(op.Value) > 0 && string(op.Value) != "null" {
			if e := json.Unmarshal(op.Value, &vals); e != nil {
				var wrapper struct {
					Members []memberInput `json:"members"`
				}
				if x := json.Unmarshal(op.Value, &wrapper); x != nil {
					return nil, fmt.Errorf("invalid members value")
				}
				vals = wrapper.Members
			}
		}
		switch o {
		case "add":
			if !strings.EqualFold(path, "members") && path != "" {
				return nil, fmt.Errorf("unsupported Group PATCH path")
			}
			ids, e := s.validateMembers(ctx, host, vals)
			if e != nil {
				return nil, e
			}
			for _, id := range ids {
				set[id] = true
			}
		case "replace":
			if !strings.EqualFold(path, "members") {
				return nil, fmt.Errorf("unsupported Group PATCH path")
			}
			ids, e := s.validateMembers(ctx, host, vals)
			if e != nil {
				return nil, e
			}
			set = map[string]bool{}
			for _, id := range ids {
				set[id] = true
			}
		case "remove":
			if strings.EqualFold(path, "members") {
				set = map[string]bool{}
				break
			}
			needle := memberPathID(path)
			if needle == "" {
				return nil, fmt.Errorf("unsupported Group PATCH remove path")
			}
			delete(set, needle)
		default:
			return nil, fmt.Errorf("unsupported Group PATCH operation")
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	return out, nil
}
func sameMembers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]int{}
	for _, v := range a {
		set[v]++
	}
	for _, v := range b {
		set[v]--
		if set[v] < 0 {
			return false
		}
	}
	return true
}
func memberPathID(path string) string {
	low := strings.ToLower(path)
	if !strings.HasPrefix(low, "members[value eq ") {
		return ""
	}
	i := strings.Index(path, "\"")
	j := strings.LastIndex(path, "\"")
	if i < 0 || j <= i {
		return ""
	}
	return path[i+1 : j]
}

func (s *Service) discovery(w http.ResponseWriter, kind string) {
	switch kind {
	case "ServiceProviderConfig":
		write(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, "patch": map[string]bool{"supported": true}, "bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0}, "filter": map[string]any{"supported": false, "maxResults": 200}, "changePassword": map[string]bool{"supported": false}, "sort": map[string]bool{"supported": false}, "etag": map[string]bool{"supported": true}, "authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Tenant Bearer Token", "description": "Tenant-scoped bearer token", "primary": true}}})
	case "Schemas":
		write(w, 200, listResponse([]any{map[string]any{"id": userSchema, "name": "User"}, map[string]any{"id": groupSchema, "name": "Group"}}, 2, 1))
	case "ResourceTypes":
		write(w, 200, listResponse([]any{map[string]any{"id": "User", "name": "User", "endpoint": "/Users", "schema": userSchema}, map[string]any{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": groupSchema}}, 2, 1))
	}
}

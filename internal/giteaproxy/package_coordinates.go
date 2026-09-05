package giteaproxy

import (
	"net/http"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/auth"
	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/tenant"
)

func packageCoordinates(r *http.Request) ([]tenant.PackageCoordinate, bool) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/packages/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		return nil, false
	}
	owner, family := parts[0], strings.ToLower(parts[1])
	if len(parts) < 3 {
		return nil, false
	}
	var name string
	switch family {
	case store.TenantPackageFamilyGeneric:
		name = parts[2]
	case store.TenantPackageFamilyNPM:
		name = parts[2]
		if strings.HasPrefix(name, "@") {
			if len(parts) < 4 || parts[3] == "" {
				return nil, true
			}
			name += "/" + parts[3]
		}
	default:
		// Other supported Gitea registries remain available for unmanaged
		// owners, but a managed tenant authorizer will reject the family.
		name = "unsupported"
	}
	if name == "" || strings.ContainsAny(owner+name, "\\") {
		return nil, family == store.TenantPackageFamilyNPM || family == store.TenantPackageFamilyGeneric
	}
	write := methodAction(r) == ActionWrite
	return []tenant.PackageCoordinate{{Owner: owner, Family: family, Name: name, Write: write, Creation: write && r.Method == http.MethodPut}}, false
}

func dockerTokenRequest(r *http.Request) (string, []tenant.PackageCoordinate, bool) {
	requested := r.URL.Query()["scope"]
	if len(requested) == 0 {
		return auth.ScopePackagesRead, nil, false
	}
	write := false
	byKey := map[string]tenant.PackageCoordinate{}
	for _, raw := range requested {
		parts := strings.SplitN(raw, ":", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return "", nil, true
		}
		resource, name := parts[0], parts[1]
		coordinateWrite := false
		creation := false
		for _, action := range strings.Split(parts[2], ",") {
			switch action {
			case "pull":
			case "push":
				coordinateWrite = true
				creation = true
				write = true
			case "delete":
				coordinateWrite = true
				write = true
			case "*":
				coordinateWrite = true
				creation = true
				write = true
			default:
				return "", nil, true
			}
		}
		// Registry-level and unknown resources are never forwarded: they are
		// not tied to a tenant owner/name allocation and can mint global JWT
		// authority (for example registry:catalog:*).
		if resource != "repository" {
			return "", nil, true
		}
		slash := strings.IndexByte(name, '/')
		if slash <= 0 || slash == len(name)-1 || strings.Contains(name, "//") || strings.ContainsAny(name, "\\ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return "", nil, true
		}
		c := tenant.PackageCoordinate{Owner: name[:slash], Family: store.TenantPackageFamilyDocker, Name: name[slash+1:], Write: coordinateWrite, Creation: creation}
		key := c.Owner + "\x00" + c.Name
		if old, ok := byKey[key]; ok {
			c.Write = c.Write || old.Write
			c.Creation = c.Creation || old.Creation
		}
		byKey[key] = c
	}
	coords := make([]tenant.PackageCoordinate, 0, len(byKey))
	for _, c := range byKey {
		coords = append(coords, c)
	}
	scope := auth.ScopePackagesRead
	if write {
		scope = auth.ScopePackagesWrite
	}
	return scope, coords, false
}

func dockerContinuationCoordinates(r *http.Request) ([]tenant.PackageCoordinate, bool) {
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	if path == r.URL.Path || path == "" {
		return nil, false
	}
	end := -1
	matchedMarker := ""
	for _, marker := range []string{"/manifests/", "/blobs/", "/tags/"} {
		if i := strings.Index(path, marker); i >= 0 && (end < 0 || i < end) {
			end = i
			matchedMarker = marker
		}
	}
	if end <= 0 {
		return nil, false
	}
	repository := path[:end]
	slash := strings.IndexByte(repository, '/')
	if slash <= 0 || slash == len(repository)-1 || strings.Contains(repository, "//") || strings.ContainsAny(repository, "\\ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return nil, true
	}
	write := methodAction(r) == ActionWrite
	return []tenant.PackageCoordinate{{Owner: repository[:slash], Family: store.TenantPackageFamilyDocker, Name: repository[slash+1:], Write: write, Creation: write && r.Method == http.MethodPut && matchedMarker == "/manifests/"}}, false
}

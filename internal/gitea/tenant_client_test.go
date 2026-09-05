package gitea

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTenantListPaginationBeyondFirstPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		count := 5
		if page == "1" {
			count = 50
		}
		if page == "" {
			t.Errorf("missing page parameter")
		}
		switch r.URL.Path {
		case "/api/v1/teams/22/members":
			users := make([]User, count)
			for i := range users {
				users[i] = User{ID: int64(i + 1), Login: "user"}
			}
			_ = json.NewEncoder(w).Encode(users)
		case "/api/v1/orgs/grasp-t/teams":
			teams := make([]Team, count)
			for i := range teams {
				teams[i] = Team{ID: int64(i + 1), Name: "team"}
			}
			_ = json.NewEncoder(w).Encode(teams)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	c := NewClient(ts.URL, "token")
	members, err := c.ListTeamMembers(t.Context(), 22)
	if err != nil || len(members) != 55 {
		t.Fatalf("members=%d err=%v", len(members), err)
	}
	teams, err := c.ListTeams(t.Context(), "grasp-t")
	if err != nil || len(teams) != 55 {
		t.Fatalf("teams=%d err=%v", len(teams), err)
	}
}

func TestTenantClientUsesTeamDrivenMembership(t *testing.T) {
	var sawTeamAdd, sawCollaborator bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/orgs/grasp-t/members/alice" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/orgs":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["visibility"] != "private" {
				t.Errorf("visibility=%v", b["visibility"])
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":11,"username":"grasp-t","visibility":"private","description":"marker"}`))
		case "POST /api/v1/orgs/grasp-t/teams":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":22,"name":"readers","description":"marker","permission":"none","units_map":{"repo.code":"read"},"organization":{"id":11,"username":"grasp-t"}}`))
		case "PUT /api/v1/teams/22/members/alice":
			sawTeamAdd = true
			w.WriteHeader(http.StatusNoContent)
		case "GET /api/v1/orgs/grasp-t/members/alice":
			w.WriteHeader(http.StatusNotFound)
		case "DELETE /api/v1/teams/22/members/alice":
			w.WriteHeader(http.StatusNoContent)
		case "PUT /api/v1/repos/grasp-t/repo/collaborators/alice":
			sawCollaborator = true
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /api/v1/repos/grasp-t/repo/collaborators/alice":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer ts.Close()
	c := NewClient(ts.URL, "token")
	ctx := t.Context()
	org, err := c.CreateManagedOrganization(ctx, "grasp-t", "marker")
	if err != nil || org.ID != 11 {
		t.Fatalf("org=%+v err=%v", org, err)
	}
	team, err := c.CreateTeam(ctx, "grasp-t", TeamSpec{Name: "readers", Description: "marker", Permission: "none", UnitsMap: map[string]string{"repo.code": "read"}})
	if err != nil || team.ID != 22 {
		t.Fatalf("team=%+v err=%v", team, err)
	}
	if err = c.AddTeamMember(ctx, 22, "alice"); err != nil {
		t.Fatal(err)
	}
	member, err := c.IsOrganizationMember(ctx, "grasp-t", "alice")
	if err != nil || member {
		t.Fatalf("member=%v err=%v", member, err)
	}
	if err = c.RemoveTeamMember(ctx, 22, "alice"); err != nil {
		t.Fatal(err)
	}
	if err = c.AddOrUpdateCollaborator(ctx, "grasp-t", "repo", "alice", "write"); err != nil {
		t.Fatal(err)
	}
	if err = c.RemoveCollaborator(ctx, "grasp-t", "repo", "alice"); err != nil {
		t.Fatal(err)
	}
	if !sawTeamAdd || !sawCollaborator {
		t.Fatal("expected team and collaborator calls")
	}
}

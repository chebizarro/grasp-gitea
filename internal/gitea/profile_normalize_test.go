// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package gitea

import (
	"strings"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/nostrprofile"
)

func TestNormalizeUserProfile(t *testing.T) {
	long := strings.Repeat("x", 300)

	cases := []struct {
		name        string
		in          nostrprofile.Profile
		wantName    string
		wantDesc    string
		wantWebsite string
	}{
		{
			name:        "basic",
			in:          nostrprofile.Profile{DisplayName: "Alice", About: "hi", Website: "https://a.example"},
			wantName:    "Alice",
			wantDesc:    "hi",
			wantWebsite: "https://a.example",
		},
		{
			name:        "javascript url dropped",
			in:          nostrprofile.Profile{Website: "javascript:alert(1)"},
			wantWebsite: "",
		},
		{
			name:        "userinfo url dropped",
			in:          nostrprofile.Profile{Website: "https://user:pw@a.example"},
			wantWebsite: "",
		},
		{
			name:        "relative url dropped",
			in:          nostrprofile.Profile{Website: "/foo"},
			wantWebsite: "",
		},
		{
			name:     "control chars stripped from name",
			in:       nostrprofile.Profile{DisplayName: "Al\x00i\x07ce\n"},
			wantName: "Alice",
		},
		{
			name:     "description keeps newlines",
			in:       nostrprofile.Profile{About: "line1\nline2\ttab"},
			wantDesc: "line1\nline2\ttab",
		},
		{
			name:     "name truncated to 100 runes",
			in:       nostrprofile.Profile{DisplayName: long},
			wantName: strings.Repeat("x", 100),
		},
		{
			name:     "description truncated to 255 runes",
			in:       nostrprofile.Profile{About: long},
			wantDesc: strings.Repeat("x", 255),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NormalizeUserProfile(tc.in)
			if f.FullName != tc.wantName {
				t.Errorf("FullName = %q, want %q", f.FullName, tc.wantName)
			}
			if f.Description != tc.wantDesc {
				t.Errorf("Description = %q, want %q", f.Description, tc.wantDesc)
			}
			if f.Website != tc.wantWebsite {
				t.Errorf("Website = %q, want %q", f.Website, tc.wantWebsite)
			}
		})
	}
}

func TestSanitizeWebsiteBounds(t *testing.T) {
	tooLong := "https://a.example/" + strings.Repeat("p", 260)
	if got := sanitizeWebsite(tooLong); got != "" {
		t.Errorf("oversized website accepted: %q", got)
	}
	if got := sanitizeWebsite("http://ok.example"); got != "http://ok.example" {
		t.Errorf("http website = %q, want kept", got)
	}
	if got := sanitizeWebsite("ftp://x.example"); got != "" {
		t.Errorf("ftp website accepted: %q", got)
	}
}

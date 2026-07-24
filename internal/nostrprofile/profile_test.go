package nostrprofile

import "testing"

func TestParseProfileContent(t *testing.T) {
	p, err := parse(`{"name":"biz","display_name":"Biz Arro","picture":"https://x/y.png","about":"hacker","website":"https://biz.example","nip05":"biz@example.com"}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.DisplayName != "Biz Arro" || p.Picture != "https://x/y.png" || p.About != "hacker" || p.Website != "https://biz.example" {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if p.IsEmpty() {
		t.Fatal("expected non-empty profile")
	}

	empty, err := parse(`{}`)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if !empty.IsEmpty() {
		t.Fatalf("expected empty profile, got %+v", empty)
	}
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nostrverify

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestValidateNilEvent(t *testing.T) {
	err := ValidateEventIDAndSignature(nil)
	if err == nil {
		t.Fatal("expected error for nil event")
	}
}

func TestValidateInvalidID(t *testing.T) {
	ev := &nostr.Event{
		ID:      "bad",
		PubKey:  "deadbeef",
		Kind:    1,
		Content: "test",
	}
	err := ValidateEventIDAndSignature(ev)
	if err == nil {
		t.Fatal("expected error for invalid event id")
	}
}

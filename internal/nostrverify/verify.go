// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package nostrverify

import (
	"fmt"

	"fiatjaf.com/nostr"
)

// ValidateEventIDAndSignature checks that the event ID is correctly
// derived from the event content and that the signature is valid.
func ValidateEventIDAndSignature(ev *nostr.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event")
	}

	if !ev.CheckID() {
		return fmt.Errorf("invalid event id")
	}

	if !ev.VerifySignature() {
		return fmt.Errorf("invalid event signature")
	}

	return nil
}

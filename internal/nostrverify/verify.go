package nostrverify

import (
	"fmt"

	"fiatjaf.com/nostr"
)

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

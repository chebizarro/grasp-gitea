package outbox

import (
	"crypto/sha256"

	"fiatjaf.com/nostr"
)

var testAuthorPubkey = nostr.Generate().Public().Hex()

func fakeEventID(label string) nostr.ID {
	return nostr.ID(sha256.Sum256([]byte(label)))
}

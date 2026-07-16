package provisioner

import "fiatjaf.com/nostr"

func mustSK(secretHex string) nostr.SecretKey {
	sk, err := nostr.SecretKeyFromHex(secretHex)
	if err != nil {
		panic(err)
	}
	return sk
}

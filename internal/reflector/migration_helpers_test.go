package reflector

import "fiatjaf.com/nostr"

func mustSK(secretHex string) nostr.SecretKey {
	sk, err := nostr.SecretKeyFromHex(secretHex)
	if err != nil {
		panic(err)
	}
	return sk
}

func derivePubHex(secretHex string) (string, error) {
	sk, err := nostr.SecretKeyFromHex(secretHex)
	if err != nil {
		return "", err
	}
	return sk.Public().Hex(), nil
}

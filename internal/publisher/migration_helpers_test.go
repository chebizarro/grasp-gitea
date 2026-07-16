package publisher

import (
	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
)

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

func encodeNpubFromHex(pubHex string) (string, error) {
	pk, err := nostr.PubKeyFromHex(pubHex)
	if err != nil {
		return "", err
	}
	return nip19.EncodeNpub(pk), nil
}

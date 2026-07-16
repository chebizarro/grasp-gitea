//go:build full

package main

import "fiatjaf.com/nostr"

func derivePubHex(secretHex string) (string, error) {
	sk, err := nostr.SecretKeyFromHex(secretHex)
	if err != nil {
		return "", err
	}
	return sk.Public().Hex(), nil
}

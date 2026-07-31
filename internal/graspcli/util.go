// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"os"
	"strings"

	gonostr "fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
)

func encodeNpub(pk gonostr.PubKey) string {
	return nip19.EncodeNpub(pk)
}

// defaultTokenName derives a token name from the local hostname so a user
// can tell their devices apart in `grasp auth list`.
func defaultTokenName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "grasp-cli"
	}
	host, _, _ = strings.Cut(host, ".")
	if len(host) > 32 {
		host = host[:32]
	}
	return host
}

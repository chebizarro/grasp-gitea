// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package publisher

import (
	"context"
	"errors"
)

// ErrBridgeSignedUserGraspListUnsupported is returned when code attempts to
// mint a kind:10317 user GRASP list with the bridge key. NIP-34 defines this
// as a user's replaceable preference list, so the only semantically valid
// bridge behavior is to relay an owner-signed event verbatim after observing
// and validating it.
var ErrBridgeSignedUserGraspListUnsupported = errors.New("bridge-signed kind:10317 user grasp lists are unsupported; use an owner-signed event")

// PublishUserGraspList deliberately refuses to create or sign kind:10317 events
// with the bridge key. A bridge-signed event would be the bridge's own GRASP
// server preference list, not the repository owner's list.
func (s *Service) PublishUserGraspList(context.Context, []string) error {
	return ErrBridgeSignedUserGraspListUnsupported
}

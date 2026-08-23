// Package policy provides the live-reloadable bridge policy snapshot.
package policy

import (
	"sync/atomic"

	"github.com/sharegap/grasp-gitea/internal/config"
)

// Snapshot contains policy values that may be reloaded without restarting.
// Its maps and slices are immutable after construction.
type Snapshot struct {
	PubkeyAllowlist map[string]struct{}
	CITriggerRepos  []string
	CIEnabled       bool
}

// Store publishes policy snapshots atomically to concurrent consumers.
type Store struct {
	current atomic.Pointer[Snapshot]
}

// New constructs a store from the initial validated configuration.
func New(cfg config.Config) *Store {
	s := &Store{}
	s.Store(cfg)
	return s
}

// Store atomically replaces the current policy with values copied from cfg.
func (s *Store) Store(cfg config.Config) {
	allowlist := make(map[string]struct{}, len(cfg.PubkeyAllowlist))
	for pubkey := range cfg.PubkeyAllowlist {
		allowlist[pubkey] = struct{}{}
	}
	s.current.Store(&Snapshot{
		PubkeyAllowlist: allowlist,
		CITriggerRepos:  append([]string(nil), cfg.CITriggerRepos...),
		CIEnabled:       cfg.CIEnabled,
	})
}

// Current returns the current immutable policy snapshot.
func (s *Store) Current() *Snapshot {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

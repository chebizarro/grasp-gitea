// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store_test

import (
	"testing"

	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/store/storetest"
)

// TestSQLiteStoreConformance runs the AuthStore conformance suite against
// the reference SQLite implementation. A future shared backend (Postgres,
// for active-active) runs exactly this suite via storetest.Run.
func TestSQLiteStoreConformance(t *testing.T) {
	open := func(t *testing.T) *store.SQLiteStore {
		st, err := store.Open(t.TempDir() + "/conformance.db")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	storetest.Run(t, func(t *testing.T) store.AuthStore { return open(t) })
	storetest.RunProposal(t, func(t *testing.T) store.ProposalStore { return open(t) })
}

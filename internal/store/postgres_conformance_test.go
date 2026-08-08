// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package store_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/store"
	"github.com/sharegap/grasp-gitea/internal/store/storetest"
)

// pgSchemaCounter isolates each conformance sub-test in its own schema, so
// the suite's fresh-store assumption holds against one shared server.
var pgSchemaCounter atomic.Int64

// TestPostgresStoreConformance runs the exact same AuthStore conformance
// suite the SQLite reference passes, against a real Postgres:
//
//	docker run -d --name grasp-pg-test -e POSTGRES_PASSWORD=grasp \
//	  -e POSTGRES_DB=grasp_test -p 127.0.0.1:5433:5432 postgres:16-alpine
//	GRASP_TEST_POSTGRES_DSN='postgres://postgres:grasp@127.0.0.1:5433/grasp_test?sslmode=disable' \
//	  go test ./internal/store/ -run PostgresStoreConformance
//
// Skipped when GRASP_TEST_POSTGRES_DSN is unset, so environments without a
// Postgres (CI without services, plain laptops) stay green.
func TestPostgresStoreConformance(t *testing.T) {
	dsn := os.Getenv("GRASP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRASP_TEST_POSTGRES_DSN not set; skipping Postgres conformance")
	}

	storetest.Run(t, func(t *testing.T) store.AuthStore {
		schema := fmt.Sprintf("conf_%d", pgSchemaCounter.Add(1))
		st, err := store.OpenPostgresInSchema(dsn, schema)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		t.Cleanup(func() {
			_ = st.DropSchema(context.Background(), schema)
			st.Close()
		})
		return st
	})
}

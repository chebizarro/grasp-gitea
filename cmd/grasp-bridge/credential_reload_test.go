// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeGiteaCredentialTarget struct {
	validationErr error
	validated     string
	active        string
}

func (f *fakeGiteaCredentialTarget) ValidateAdminToken(_ context.Context, token, _ string) error {
	f.validated = token
	return f.validationErr
}

func (f *fakeGiteaCredentialTarget) SetAdminToken(token string) error {
	f.active = token
	return nil
}

type fakeRegistryCredentialTarget struct{ active string }

func (f *fakeRegistryCredentialTarget) SetToken(token string) error {
	f.active = token
	return nil
}

func TestReloadGiteaAdminCredentialAppliesValidatedCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("replacement-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &fakeGiteaCredentialTarget{active: "original-token"}
	monitor := &fakeRegistryCredentialTarget{active: "original-token"}

	if err := reloadGiteaAdminCredential(context.Background(), path, "grasp-admin", client, monitor); err != nil {
		t.Fatalf("reloadGiteaAdminCredential: %v", err)
	}
	if client.active != "replacement-token" || monitor.active != "replacement-token" {
		t.Fatalf("credential targets = (%q, %q), want replacement-token", client.active, monitor.active)
	}
}

func TestReloadGiteaAdminCredentialKeepsActiveCredentialOnValidationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("invalid-candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &fakeGiteaCredentialTarget{active: "original-token", validationErr: errors.New("unauthorized")}
	monitor := &fakeRegistryCredentialTarget{active: "original-token"}

	if err := reloadGiteaAdminCredential(context.Background(), path, "grasp-admin", client, monitor); err == nil {
		t.Fatal("reloadGiteaAdminCredential accepted an invalid candidate")
	}
	if client.active != "original-token" || monitor.active != "original-token" {
		t.Fatalf("credential targets changed to (%q, %q)", client.active, monitor.active)
	}
}

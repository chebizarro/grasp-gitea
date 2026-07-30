// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/sharegap/grasp-gitea/internal/config"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func TestCredentialCipherRoundTrip(t *testing.T) {
	cipher, err := NewCredentialCipher([]config.CredentialKey{{ID: "k1", Key: testKey(t)}})
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}

	aad := PATCredentialAAD(42, 1, "grasp-pat-42-1", "k1")
	blob, keyID, err := cipher.Seal([]byte("secret-pat"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if keyID != "k1" {
		t.Fatalf("keyID = %q, want k1", keyID)
	}
	if bytes.Contains(blob, []byte("secret-pat")) {
		t.Fatal("ciphertext contains plaintext")
	}

	plain, err := cipher.Open(blob, keyID, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plain) != "secret-pat" {
		t.Fatalf("plaintext = %q", plain)
	}
}

func TestCredentialCipherRejectsWrongAAD(t *testing.T) {
	cipher, err := NewCredentialCipher([]config.CredentialKey{{ID: "k1", Key: testKey(t)}})
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}
	blob, keyID, err := cipher.Seal([]byte("secret"), PATCredentialAAD(1, 1, "n", "k1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := cipher.Open(blob, keyID, PATCredentialAAD(2, 1, "n", "k1")); err == nil {
		t.Fatal("Open succeeded with mismatched AAD (ciphertext moved between rows)")
	}
}

func TestCredentialCipherOldKeyDecryptsNewKeyEncrypts(t *testing.T) {
	oldKey := config.CredentialKey{ID: "old", Key: testKey(t)}
	oldCipher, err := NewCredentialCipher([]config.CredentialKey{oldKey})
	if err != nil {
		t.Fatalf("old cipher: %v", err)
	}
	aad := PATCredentialAAD(7, 3, "pat", "old")
	blob, keyID, err := oldCipher.Seal([]byte("legacy"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rotated, err := NewCredentialCipher([]config.CredentialKey{{ID: "new", Key: testKey(t)}, oldKey})
	if err != nil {
		t.Fatalf("rotated cipher: %v", err)
	}
	if rotated.ActiveKeyID() != "new" {
		t.Fatalf("ActiveKeyID = %q, want new", rotated.ActiveKeyID())
	}
	plain, err := rotated.Open(blob, keyID, aad)
	if err != nil {
		t.Fatalf("Open with old key after rotation: %v", err)
	}
	if string(plain) != "legacy" {
		t.Fatalf("plaintext = %q", plain)
	}
	if !rotated.NeedsReencrypt(keyID) {
		t.Fatal("NeedsReencrypt(old) = false, want true")
	}
	if rotated.NeedsReencrypt("new") {
		t.Fatal("NeedsReencrypt(active) = true, want false")
	}
}

func TestCredentialCipherUnknownKeyID(t *testing.T) {
	cipher, err := NewCredentialCipher([]config.CredentialKey{{ID: "k1", Key: testKey(t)}})
	if err != nil {
		t.Fatalf("NewCredentialCipher: %v", err)
	}
	blob, _, err := cipher.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := cipher.Open(blob, "missing", nil); err == nil {
		t.Fatal("Open succeeded with unknown key id")
	}
}

func TestNewCredentialCipherValidation(t *testing.T) {
	if _, err := NewCredentialCipher(nil); err == nil {
		t.Fatal("empty ring accepted")
	}
	if _, err := NewCredentialCipher([]config.CredentialKey{{ID: "short", Key: []byte("tiny")}}); err == nil {
		t.Fatal("short key accepted")
	}
	key := testKey(t)
	if _, err := NewCredentialCipher([]config.CredentialKey{{ID: "a", Key: key}, {ID: "a", Key: key}}); err == nil {
		t.Fatal("duplicate key id accepted")
	}
}

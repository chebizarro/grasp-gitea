// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"strconv"

	"github.com/sharegap/grasp-gitea/internal/config"
)

// CredentialCipher encrypts hidden downstream credentials (Gitea PATs) at rest
// using a versioned AES-256-GCM key ring. The first configured key encrypts;
// every configured key may decrypt, enabling online key rotation. It is
// deliberately independent of the NIP-46 signer master key.
type CredentialCipher struct {
	activeID string
	keys     map[string][]byte
}

// NewCredentialCipher builds a cipher from the parsed GRASP_CREDENTIAL_KEYS
// ring. The slice must be non-empty; entry order determines the active key.
func NewCredentialCipher(ring []config.CredentialKey) (*CredentialCipher, error) {
	if len(ring) == 0 {
		return nil, fmt.Errorf("credential cipher requires at least one key")
	}
	keys := make(map[string][]byte, len(ring))
	for _, entry := range ring {
		if entry.ID == "" || len(entry.Key) != 32 {
			return nil, fmt.Errorf("credential key %q must be 32 bytes with a non-empty id", entry.ID)
		}
		if _, dup := keys[entry.ID]; dup {
			return nil, fmt.Errorf("credential key id %q is duplicated", entry.ID)
		}
		keyCopy := make([]byte, 32)
		copy(keyCopy, entry.Key)
		keys[entry.ID] = keyCopy
	}
	return &CredentialCipher{activeID: ring[0].ID, keys: keys}, nil
}

// ActiveKeyID reports the key id used for new encryptions.
func (c *CredentialCipher) ActiveKeyID() string {
	return c.activeID
}

// Seal encrypts plaintext with the active key and the supplied additional
// authenticated data. The returned blob is nonce||ciphertext.
func (c *CredentialCipher) Seal(plaintext, aad []byte) (blob []byte, keyID string, err error) {
	aead, err := c.aead(c.activeID)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("credential nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, c.activeID, nil
}

// Open decrypts a nonce||ciphertext blob produced by Seal with the named key
// and identical additional authenticated data.
func (c *CredentialCipher) Open(blob []byte, keyID string, aad []byte) ([]byte, error) {
	aead, err := c.aead(keyID)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+1 {
		return nil, fmt.Errorf("credential ciphertext too short")
	}
	nonce, sealed := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("credential decrypt with key %q failed", keyID)
	}
	return plaintext, nil
}

// NeedsReencrypt reports whether a record encrypted under keyID should be
// lazily re-encrypted with the active key.
func (c *CredentialCipher) NeedsReencrypt(keyID string) bool {
	return keyID != c.activeID
}

func (c *CredentialCipher) aead(keyID string) (cipher.AEAD, error) {
	key, ok := c.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown credential key id %q", keyID)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("credential cipher init: %w", err)
	}
	return cipher.NewGCM(block)
}

// PATCredentialAAD binds a PAT ciphertext to its identifying row so a
// ciphertext copied onto another row fails authentication. It must contain
// every immutable field named in the stored record: Gitea user id, generation,
// PAT name, and encrypting key id.
func PATCredentialAAD(giteaUserID, generation int64, patName, keyID string) []byte {
	return []byte("grasp-pat-v1|" + strconv.FormatInt(giteaUserID, 10) + "|" +
		strconv.FormatInt(generation, 10) + "|" + patName + "|" + keyID)
}

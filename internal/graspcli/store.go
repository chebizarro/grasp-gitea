// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

// Package graspcli implements the grasp client CLI: bridge token acquisition
// (NIP-98 via nsec or NIP-46 bunker), credential storage (OS keychain with a
// 0600 file fallback), the git credential-helper protocol, and package
// registry configuration helpers.
package graspcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// keyringService namespaces grasp secrets in the OS keychain.
const keyringService = "grasp-bridge"

// Credential is one stored bridge token. The secret itself lives either in
// the OS keychain (InKeychain=true) or inline in the metadata file, which is
// then the 0600 fallback.
type Credential struct {
	// Server is the bridge origin, e.g. https://git.example.com.
	Server string `json:"server"`
	// Host is the URL host, the git credential-helper matching key.
	Host string `json:"host"`
	// Scheme is the origin scheme. A credential stored for https must never
	// be disclosed to a plaintext http request for the same host.
	Scheme string `json:"scheme"`
	// Npub is the Basic username the bridge expects.
	Npub string `json:"npub"`
	// TokenID is the bridge-side id used for revoke/rotate.
	TokenID   string    `json:"token_id"`
	Name      string    `json:"name,omitempty"`
	Scopes    []string  `json:"scopes,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// Token is the secret when stored inline (file fallback).
	Token string `json:"token,omitempty"`
	// InKeychain marks the secret as living in the OS keychain under
	// (keyringService, Host).
	InKeychain bool `json:"in_keychain,omitempty"`
}

// Keyring abstracts the OS keychain so tests can substitute a fake and the
// file fallback can be forced.
type Keyring interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type systemKeyring struct{}

func (systemKeyring) Set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}
func (systemKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}
func (systemKeyring) Delete(service, user string) error { return keyring.Delete(service, user) }

// disabledKeyring always fails, forcing the inline file fallback.
type disabledKeyring struct{}

var errKeyringDisabled = errors.New("keychain disabled")

func (disabledKeyring) Set(string, string, string) error   { return errKeyringDisabled }
func (disabledKeyring) Get(string, string) (string, error) { return "", errKeyringDisabled }
func (disabledKeyring) Delete(string, string) error        { return errKeyringDisabled }

// Store persists credentials: metadata in a 0600 JSON file, secrets in the
// OS keychain when available, inline otherwise.
type Store struct {
	path string
	ring Keyring
}

// NewStore opens the credential store rooted at dir (default: user config
// dir + /grasp). useKeychain=false forces the file fallback.
func NewStore(dir string, useKeychain bool) (*Store, error) {
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("resolve config dir: %w", err)
		}
		dir = filepath.Join(base, "grasp")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	var ring Keyring = systemKeyring{}
	if !useKeychain {
		ring = disabledKeyring{}
	}
	return &Store{path: filepath.Join(dir, "credentials.json"), ring: ring}, nil
}

// WithKeyring substitutes the keychain implementation (tests).
func (s *Store) WithKeyring(ring Keyring) *Store {
	s.ring = ring
	return s
}

func (s *Store) load() ([]Credential, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var creds []Credential
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("decode %s: %w", s.path, err)
	}
	return creds, nil
}

func (s *Store) save(creds []Credential) error {
	sort.Slice(creds, func(i, j int) bool { return creds[i].Host < creds[j].Host })
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	// Write via a same-directory temp file so a crash never leaves a
	// truncated store, and the file is 0600 from its first byte.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Put stores a credential for its server, replacing any existing entry for
// the same host. The secret goes to the keychain when possible; on any
// keychain error it is stored inline in the 0600 file instead.
func (s *Store) Put(cred Credential) (usedKeychain bool, err error) {
	if cred.Server == "" || cred.Token == "" || cred.Npub == "" {
		return false, fmt.Errorf("credential requires server, npub, and token")
	}
	parsed, err := url.Parse(cred.Server)
	if err != nil || parsed.Host == "" {
		return false, fmt.Errorf("server must be an absolute URL, got %q", cred.Server)
	}
	cred.Host = parsed.Host
	cred.Scheme = parsed.Scheme

	unlock, err := s.lock()
	if err != nil {
		return false, err
	}
	defer unlock()

	switch err := s.ring.Set(keyringService, cred.Host, cred.Token); {
	case err == nil:
		cred.InKeychain = true
		cred.Token = ""
		usedKeychain = true
	case errors.Is(err, errKeyringDisabled):
		// Explicit --no-keychain opt-in: inline 0600 storage.
	case errors.Is(err, keyring.ErrUnsupportedPlatform):
		// No keychain exists on this platform at all; the 0600 file is the
		// only option and needs no opt-in.
	default:
		// A keychain exists but failed (locked, denied, dbus down). Silently
		// downgrading a secret to file storage is not this tool's call.
		return false, fmt.Errorf("keychain store failed: %w (re-run with --no-keychain to explicitly use the 0600 credentials file)", err)
	}

	creds, err := s.load()
	if err != nil {
		return usedKeychain, err
	}
	out := creds[:0]
	for _, c := range creds {
		if c.Host != cred.Host {
			out = append(out, c)
		}
	}
	out = append(out, cred)
	return usedKeychain, s.save(out)
}

// Get returns the credential for a host with its secret resolved.
func (s *Store) Get(host string) (Credential, bool, error) {
	creds, err := s.load()
	if err != nil {
		return Credential{}, false, err
	}
	for _, c := range creds {
		if !strings.EqualFold(c.Host, host) {
			continue
		}
		if c.InKeychain {
			secret, err := s.ring.Get(keyringService, c.Host)
			if err != nil {
				return Credential{}, false, fmt.Errorf("keychain lookup for %s: %w", c.Host, err)
			}
			c.Token = secret
		}
		return c, true, nil
	}
	return Credential{}, false, nil
}

// List returns stored credentials without resolving secrets.
func (s *Store) List() ([]Credential, error) {
	creds, err := s.load()
	for i := range creds {
		creds[i].Token = ""
	}
	return creds, err
}

// lock takes a best-effort advisory lock so two grasp processes cannot
// interleave load-modify-save cycles and drop each other's writes.
func (s *Store) lock() (func(), error) {
	lockPath := s.path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open store lock: %w", err)
	}
	if err := flockExclusive(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock credential store: %w", err)
	}
	return func() {
		flockRelease(f)
		f.Close()
	}, nil
}

// Delete removes a host's credential from both file and keychain.
func (s *Store) Delete(host string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	creds, err := s.load()
	if err != nil {
		return err
	}
	out := creds[:0]
	removed := false
	for _, c := range creds {
		if strings.EqualFold(c.Host, host) {
			removed = true
			if c.InKeychain {
				if err := s.ring.Delete(keyringService, c.Host); err != nil && !errors.Is(err, keyring.ErrNotFound) && !errors.Is(err, errKeyringDisabled) {
					return fmt.Errorf("keychain delete for %s: %w", c.Host, err)
				}
			}
			continue
		}
		out = append(out, c)
	}
	if !removed {
		return nil
	}
	return s.save(out)
}

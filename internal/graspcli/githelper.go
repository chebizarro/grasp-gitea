// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// GitCredential implements the git credential-helper protocol
// (https://git-scm.com/docs/gitcredentials): key=value lines on stdin, and
// for `get`, matching credentials on stdout. Configure with:
//
//	git config --global credential.https://git.example.com.helper "grasp git-credential"
//
// Operations:
//
//	get   emit username/password when the request host has a stored token
//	store no-op: grasp manages its own storage, and git's plaintext
//	      ~/.git-credentials must never hold a bridge token
//	erase drop the stored credential, but only when the failing credential
//	      git reports is the one we hold; a transient 401 with someone
//	      else's credential must not destroy ours
func GitCredential(op string, stdin io.Reader, stdout io.Writer, store *Store) error {
	switch op {
	case "get", "store", "erase":
	default:
		return fmt.Errorf("unsupported git credential operation %q", op)
	}
	attrs, err := parseCredentialAttrs(stdin)
	if err != nil {
		return err
	}
	host := attrs["host"]
	if host == "" {
		// Nothing to match on; stay silent so git falls through to other
		// helpers.
		return nil
	}
	protocol := attrs["protocol"]
	if protocol != "" && protocol != "https" && protocol != "http" {
		return nil
	}

	switch op {
	case "get":
		cred, found, err := store.Get(host)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if protocol != "" && cred.Scheme != "" && protocol != cred.Scheme {
			// Never disclose an https credential to a plaintext http request
			// for the same host (or vice versa): git would transmit the
			// token before any redirect to the real origin.
			return nil
		}
		if user := attrs["username"]; user != "" && !strings.EqualFold(user, cred.Npub) {
			// git already has a different username for this URL; our
			// credential is not the one being asked for.
			return nil
		}
		fmt.Fprintf(stdout, "username=%s\n", cred.Npub)
		fmt.Fprintf(stdout, "password=%s\n", cred.Token)
		return nil

	case "store":
		return nil

	default: // erase
		cred, found, err := store.Get(host)
		if err != nil || !found {
			return err
		}
		if user := attrs["username"]; user != "" && !strings.EqualFold(user, cred.Npub) {
			return nil
		}
		if pass := attrs["password"]; pass != "" && pass != cred.Token {
			return nil
		}
		return store.Delete(host)
	}
}

// parseCredentialAttrs reads the protocol's key=value lines. Values may
// contain '='; a blank line terminates the list.
func parseCredentialAttrs(r io.Reader) (map[string]string, error) {
	attrs := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			continue
		}
		attrs[key] = value
	}
	return attrs, scanner.Err()
}

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	gonostr "fiatjaf.com/nostr"
	"fiatjaf.com/nostr/keyer"
	casnostr "git.sharegap.net/cascadia/cascadia-go/nostr"
	"golang.org/x/term"
)

// signerEnv is the environment variable holding the signer input. Secrets
// are never accepted on the command line: argv leaks into shell history and
// process listings.
const signerEnv = "GRASP_SIGNER"

// ResolveSigner produces a signing identity from, in order of precedence:
//
//  1. signerFile: a 0600 file whose first line is the input
//  2. the GRASP_SIGNER environment variable
//  3. an interactive prompt on the controlling terminal (never echoed)
//
// The input may be an nsec, hex secret key, ncryptsec (prompted for its
// password), or a NIP-46 bunker:// URL / NIP-05 identifier (remote signing;
// any bunker auth challenge URL is printed to stderr for the user to open).
func ResolveSigner(ctx context.Context, signerFile string, stderr io.Writer) (casnostr.Signer, error) {
	input, err := signerInput(signerFile, stderr)
	if err != nil {
		return nil, err
	}
	opts := &keyer.SignerOptions{
		BunkerAuthHandler: func(url string) {
			fmt.Fprintf(stderr, "bunker requests authorization; open:\n  %s\n", url)
		},
		PasswordHandler: func(ctx context.Context) string {
			secret, err := promptSecret(stderr, "ncryptsec password: ")
			if err != nil {
				return ""
			}
			return secret
		},
	}
	signer, err := keyer.New(ctx, gonostr.NewPool(), input, opts)
	if err != nil {
		return nil, fmt.Errorf("build signer: %w", err)
	}
	return signer, nil
}

func signerInput(signerFile string, stderr io.Writer) (string, error) {
	if signerFile != "" {
		info, err := os.Stat(signerFile)
		if err != nil {
			return "", fmt.Errorf("signer file: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("signer file %s is group/world accessible (%v); chmod 600 it", signerFile, info.Mode().Perm())
		}
		data, err := os.ReadFile(signerFile)
		if err != nil {
			return "", fmt.Errorf("signer file: %w", err)
		}
		line, _, _ := strings.Cut(string(data), "\n")
		line = strings.TrimSpace(line)
		if line == "" {
			return "", fmt.Errorf("signer file %s is empty", signerFile)
		}
		return line, nil
	}
	if env := strings.TrimSpace(os.Getenv(signerEnv)); env != "" {
		return env, nil
	}
	return promptSecret(stderr, "nsec / hex key / bunker:// URL: ")
}

// promptSecret reads a secret from the controlling terminal without echo.
func promptSecret(stderr io.Writer, prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal for secret prompt (set %s or use --signer-file): %w", signerEnv, err)
	}
	defer tty.Close()
	fmt.Fprint(stderr, prompt)
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	trimmed := strings.TrimSpace(string(secret))
	if trimmed == "" {
		return "", fmt.Errorf("empty secret")
	}
	return trimmed, nil
}

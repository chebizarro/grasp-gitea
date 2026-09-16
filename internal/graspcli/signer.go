// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	gonostr "fiatjaf.com/nostr"
	"fiatjaf.com/nostr/keyer"
	"fiatjaf.com/nostr/nip19"
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
	return ResolveSignerWithClientKey(ctx, signerFile, "", stderr)
}

// ResolveSignerWithClientKey is ResolveSigner with optional support for the
// split NIP-46 form used by ngit/OpenClaw: the public bunker URI and the
// client's private application key live in separate 0600 files.
func ResolveSignerWithClientKey(ctx context.Context, signerFile, bunkerClientKeyFile string, stderr io.Writer) (casnostr.Signer, error) {
	input, err := signerInput(signerFile, stderr)
	if err != nil {
		return nil, err
	}
	input, err = normalizeSignerInput(input)
	if err != nil {
		return nil, fmt.Errorf("build signer: invalid signer input (details redacted)")
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
	if bunkerClientKeyFile != "" {
		clientKeyInput, err := signerInput(bunkerClientKeyFile, stderr)
		if err != nil {
			return nil, fmt.Errorf("bunker client key file: %w", err)
		}
		if prefix, decoded, decodeErr := nip19.Decode(clientKeyInput); decodeErr == nil && prefix == "nsec" {
			opts.BunkerClientSecretKey = decoded.(gonostr.SecretKey)
		} else if key, hexErr := gonostr.SecretKeyFromHex(clientKeyInput); hexErr == nil {
			opts.BunkerClientSecretKey = key
		} else {
			return nil, fmt.Errorf("bunker client key file: invalid secret key (details redacted)")
		}
	}
	signer, err := keyer.New(ctx, gonostr.NewPool(), input, opts)
	if err != nil {
		// keyer historically included the complete untrusted input in format
		// errors. That input may be an nsec or a bunker URI carrying a client
		// connection secret, so never propagate the underlying text.
		return nil, fmt.Errorf("build signer: %s", safeSignerFailure(err))
	}
	return signer, nil
}

func safeSignerFailure(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "connect_secret mismatch"):
		return "NIP-46 connection secret mismatch (details redacted)"
	case strings.Contains(message, "unsupported input"), strings.Contains(message, "invalid bunker"):
		return "unsupported signer input (details redacted)"
	case strings.Contains(message, "unauthorized"), strings.Contains(message, "permission denied"):
		return "NIP-46 signer denied authorization (details redacted)"
	case strings.Contains(message, "connection refused"):
		return "NIP-46 connection refused (details redacted)"
	case strings.Contains(message, "connection failure"), strings.Contains(message, "websocket"):
		return "NIP-46 relay connection failed (details redacted)"
	case strings.Contains(message, "deadline exceeded"), strings.Contains(message, "timed out"):
		return "NIP-46 signer timed out (details redacted)"
	default:
		return "signer initialization failed (details redacted)"
	}
}

// normalizeSignerInput accepts the npub authority form emitted by deployed
// Cascadia tooling and converts it to the hex authority required by the
// upstream NIP-46 parser. Query values (including the client secret) are
// preserved in memory and must never be included in an error.
func normalizeSignerInput(input string) (string, error) {
	if !strings.HasPrefix(input, "bunker://") {
		return input, nil
	}
	u, err := url.Parse(input)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid bunker URI")
	}
	if !strings.HasPrefix(u.Host, "npub1") {
		return input, nil
	}
	prefix, decoded, err := nip19.Decode(u.Host)
	if err != nil || prefix != "npub" {
		return "", fmt.Errorf("invalid bunker npub")
	}
	pubkey, ok := decoded.(gonostr.PubKey)
	if !ok {
		return "", fmt.Errorf("invalid bunker npub payload")
	}
	u.Host = pubkey.Hex()
	return u.String(), nil
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

// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const usage = `grasp — nostr client for a GRASP Gitea bridge

Usage:
  grasp auth login   --server URL [--name N] [--scopes s1,s2] [--ttl DUR] [--signer-file F] [--no-keychain] [--show-token]
  grasp auth list    --server URL [--signer-file F]
  grasp auth revoke  --server URL --id TOKEN_ID [--signer-file F]
  grasp auth rotate  --server URL --id TOKEN_ID [--name N] [--scopes s1,s2] [--ttl DUR] [--signer-file F] [--no-keychain] [--show-token]
  grasp auth status                       stored credentials (no secrets)
  grasp auth token   HOST                 print the stored token (for piping)
  grasp auth logout  HOST                 delete the stored credential
  grasp git-credential (get|store|erase)  git credential-helper protocol
  grasp setup (npm|pypi|cargo|docker|nuget) --host HOST [--owner O] [--show-token]

The signing identity (nsec, hex key, ncryptsec, or bunker:// URL) is read
from --signer-file, the GRASP_SIGNER environment variable, or an interactive
prompt — never from the command line.

Scopes: git:read git:write packages:read packages:write
`

// Run executes the CLI and returns a process exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "auth":
		err = runAuth(ctx, args[1:], stdout, stderr)
	case "git-credential":
		err = runGitCredential(args[1:], stdin, stdout)
	case "setup":
		err = runSetup(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

type authFlags struct {
	server     string
	name       string
	scopes     string
	ttl        time.Duration
	id         string
	signerFile string
	noKeychain bool
	showToken  bool
	configDir  string
}

func bindAuthFlags(fs *flag.FlagSet) *authFlags {
	f := &authFlags{}
	fs.StringVar(&f.server, "server", "", "bridge origin, e.g. https://git.example.com")
	fs.StringVar(&f.name, "name", "", "token name (default: this hostname)")
	fs.StringVar(&f.scopes, "scopes", "", "comma-separated scopes (default: server default)")
	fs.DurationVar(&f.ttl, "ttl", 0, "token lifetime, e.g. 720h (default: server default)")
	fs.StringVar(&f.id, "id", "", "token id (revoke/rotate)")
	fs.StringVar(&f.signerFile, "signer-file", "", "0600 file holding the signer input")
	fs.BoolVar(&f.noKeychain, "no-keychain", false, "store the token in the 0600 file instead of the OS keychain")
	fs.BoolVar(&f.showToken, "show-token", false, "print the plaintext token to stdout")
	fs.StringVar(&f.configDir, "config-dir", "", "override the grasp config directory")
	return f
}

func runAuth(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return fmt.Errorf("auth requires a subcommand\n\n%s", usage)
	}
	sub, rest := args[0], args[1:]

	// Storage-only subcommands never need a signer.
	switch sub {
	case "status", "token", "logout":
		return runAuthLocal(sub, rest, stdout)
	}

	fs := flag.NewFlagSet("auth "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := bindAuthFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if f.server == "" {
		return fmt.Errorf("--server is required")
	}

	signer, err := ResolveSigner(ctx, f.signerFile, stderr)
	if err != nil {
		return err
	}
	client, err := NewClient(f.server, signer)
	if err != nil {
		return err
	}

	switch sub {
	case "login":
		return doMint(ctx, client, f, stdout, stderr, "")
	case "rotate":
		if f.id == "" {
			return fmt.Errorf("--id is required for rotate")
		}
		return doMint(ctx, client, f, stdout, stderr, f.id)
	case "list":
		tokens, err := client.List(ctx)
		if err != nil {
			return err
		}
		if len(tokens) == 0 {
			fmt.Fprintln(stdout, "no tokens")
			return nil
		}
		for _, t := range tokens {
			fmt.Fprintf(stdout, "%s  %-12s  %-8s  …%s  scopes=%s  expires=%s\n",
				t.ID, t.Name, t.State, t.Suffix, strings.Join(t.Scopes, ","),
				t.ExpiresAt.Format(time.RFC3339))
		}
		return nil
	case "revoke":
		if f.id == "" {
			return fmt.Errorf("--id is required for revoke")
		}
		if err := client.Revoke(ctx, f.id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "revoked %s\n", f.id)
		return nil
	default:
		return fmt.Errorf("unknown auth subcommand %q", sub)
	}
}

func doMint(ctx context.Context, client *Client, f *authFlags, stdout, stderr io.Writer, rotateID string) error {
	req := MintRequest{Name: f.name}
	if req.Name == "" {
		req.Name = defaultTokenName()
	}
	if f.scopes != "" {
		req.Scopes = strings.Split(f.scopes, ",")
	}
	if f.ttl > 0 {
		req.TTLSeconds = int64(f.ttl / time.Second)
	}

	var minted TokenMint
	var err error
	if rotateID == "" {
		minted, err = client.Mint(ctx, req)
	} else {
		minted, err = client.Rotate(ctx, rotateID, req)
	}
	if err != nil {
		return err
	}

	pubkey, err := client.signer.GetPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("resolve npub: %w", err)
	}
	npub := encodeNpub(pubkey)

	store, err := NewStore(f.configDir, !f.noKeychain)
	if err != nil {
		return revokeAfterStorageFailure(ctx, client, minted.ID, err)
	}

	// Remember any token this login replaces so it can be revoked remotely
	// rather than stranded active with no local reference.
	var replaced Credential
	var hadPrevious bool
	if prevHost := hostOf(client.base); prevHost != "" {
		prev, found, lookupErr := store.Get(prevHost)
		if lookupErr == nil && found && prev.TokenID != minted.ID && prev.TokenID != rotateID {
			replaced, hadPrevious = prev, true
		}
	}

	usedKeychain, err := store.Put(Credential{
		Server: client.base, Npub: npub,
		TokenID: minted.ID, Name: minted.Name,
		Scopes: minted.Scopes, ExpiresAt: minted.ExpiresAt,
		Token: minted.Token,
	})
	if err != nil {
		return revokeAfterStorageFailure(ctx, client, minted.ID, err)
	}

	if hadPrevious {
		if err := client.Revoke(ctx, replaced.TokenID); err != nil {
			fmt.Fprintf(stderr, "warning: replaced token %s is still active on the bridge and could not be revoked: %v\n", replaced.TokenID, err)
		} else {
			fmt.Fprintf(stdout, "revoked replaced token %s\n", replaced.TokenID)
		}
	}

	where := "OS keychain"
	if !usedKeychain {
		where = "0600 credentials file"
	}
	fmt.Fprintf(stdout, "minted token %s (%s) for %s\n", minted.ID, minted.Name, npub)
	fmt.Fprintf(stdout, "scopes:  %s\n", strings.Join(minted.Scopes, ","))
	fmt.Fprintf(stdout, "expires: %s\n", minted.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(stdout, "stored:  %s\n", where)
	if f.showToken {
		fmt.Fprintln(stdout, minted.Token)
	} else {
		fmt.Fprintln(stdout, "token stored; use `grasp auth token <host>` to print it")
	}
	// The empty helper line first resets any inherited helpers (such as a
	// global plaintext `store`), which would otherwise ALSO be asked to
	// persist this token.
	fmt.Fprintf(stderr, "git setup:\n")
	fmt.Fprintf(stderr, "  git config --global credential.%s.helper ''\n", client.base)
	fmt.Fprintf(stderr, "  git config --global --add credential.%s.helper '!grasp git-credential'\n", client.base)
	return nil
}

// revokeAfterStorageFailure keeps a mint/rotate transactional: a token we
// cannot store must not stay active on the bridge, because nothing else
// holds its plaintext.
func revokeAfterStorageFailure(ctx context.Context, client *Client, tokenID string, cause error) error {
	if revokeErr := client.Revoke(ctx, tokenID); revokeErr != nil {
		return fmt.Errorf("storing minted token %s failed (%v) AND revoking it failed (%v): revoke it manually with `grasp auth revoke --id %s`",
			tokenID, cause, revokeErr, tokenID)
	}
	return fmt.Errorf("storing the minted token failed (it has been revoked, nothing is stranded): %w", cause)
}

func hostOf(server string) string {
	parsed, err := url.Parse(server)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func runAuthLocal(sub string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("auth "+sub, flag.ContinueOnError)
	configDir := fs.String("config-dir", "", "override the grasp config directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := NewStore(*configDir, true)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		creds, err := store.List()
		if err != nil {
			return err
		}
		if len(creds) == 0 {
			fmt.Fprintln(stdout, "no stored credentials")
			return nil
		}
		for _, c := range creds {
			place := "file"
			if c.InKeychain {
				place = "keychain"
			}
			fmt.Fprintf(stdout, "%s  %s  token=%s (%s)  scopes=%s  expires=%s\n",
				c.Host, c.Npub, c.TokenID, place, strings.Join(c.Scopes, ","),
				c.ExpiresAt.Format(time.RFC3339))
		}
		return nil
	case "token":
		host, err := hostArg(fs.Args())
		if err != nil {
			return err
		}
		cred, found, err := store.Get(host)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("no credential stored for %s", host)
		}
		fmt.Fprintln(stdout, cred.Token)
		return nil
	case "logout":
		host, err := hostArg(fs.Args())
		if err != nil {
			return err
		}
		cred, found, _ := store.Get(host)
		if err := store.Delete(host); err != nil {
			return err
		}
		if found {
			fmt.Fprintf(stdout, "local credential for %s removed.\n", host)
			fmt.Fprintf(stdout, "note: token %s is STILL ACTIVE on the bridge; revoke it with:\n", cred.TokenID)
			fmt.Fprintf(stdout, "  grasp auth revoke --server %s --id %s\n", cred.Server, cred.TokenID)
		}
		return nil
	}
	return fmt.Errorf("unknown auth subcommand %q", sub)
}

func runGitCredential(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 1 {
		return fmt.Errorf("git-credential requires an operation (get|store|erase)")
	}
	op := args[0]
	var configDir string
	if len(args) > 2 && args[1] == "--config-dir" {
		configDir = args[2]
	}
	store, err := NewStore(configDir, true)
	if err != nil {
		return err
	}
	return GitCredential(op, stdin, stdout, store)
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return fmt.Errorf("setup requires a target (npm|pypi|cargo|docker|nuget)")
	}
	kind := args[0]
	fs := flag.NewFlagSet("setup "+kind, flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "", "bridge host, e.g. git.example.com")
	owner := fs.String("owner", "", "package owner (user or org)")
	showToken := fs.Bool("show-token", false, "embed the real token instead of a placeholder")
	configDir := fs.String("config-dir", "", "override the grasp config directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *host == "" {
		return fmt.Errorf("--host is required")
	}
	store, err := NewStore(*configDir, true)
	if err != nil {
		return err
	}
	cred, found, err := store.Get(*host)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no credential stored for %s; run `grasp auth login` first", *host)
	}
	if !*showToken {
		cred.Token = ""
	}
	return SetupSnippet(kind, cred, *owner, *showToken, stdout)
}

func hostArg(args []string) (string, error) {
	if len(args) != 1 || args[0] == "" {
		return "", fmt.Errorf("exactly one HOST argument is required")
	}
	if strings.Contains(args[0], "://") {
		parsed, err := url.Parse(args[0])
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("invalid host %q", args[0])
		}
		return parsed.Host, nil
	}
	return args[0], nil
}

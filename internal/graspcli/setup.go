// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package graspcli

import (
	"fmt"
	"io"
	"net/url"
	"strings"
)

// SetupSnippet prints ready-to-paste configuration for a package client.
// The token itself is only embedded with showToken; otherwise a placeholder
// is printed so real secrets never land in scrollback by accident.
func SetupSnippet(kind string, cred Credential, owner string, showToken bool, w io.Writer) error {
	parsed, err := url.Parse(cred.Server)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("credential has no valid server URL")
	}
	token := "<run: grasp auth token " + parsed.Host + ">"
	if showToken {
		token = cred.Token
	}
	if owner == "" {
		owner = "<owner>"
	}
	hostPort := parsed.Host
	base := strings.TrimRight(cred.Server, "/")

	switch kind {
	case "npm":
		fmt.Fprintf(w, "# %s/.npmrc\n", "~")
		fmt.Fprintf(w, "@%s:registry=%s/api/packages/%s/npm/\n", owner, base, owner)
		fmt.Fprintf(w, "//%s/api/packages/%s/npm/:_authToken=%s\n", hostPort, owner, token)

	case "pypi":
		fmt.Fprintf(w, "# ~/.pypirc (publish) — password is the bridge token\n")
		fmt.Fprintf(w, "[distutils]\nindex-servers = grasp\n\n")
		fmt.Fprintf(w, "[grasp]\nrepository = %s/api/packages/%s/pypi\nusername = %s\npassword = %s\n\n", base, owner, cred.Npub, token)
		fmt.Fprintf(w, "# pip install (read):\n")
		fmt.Fprintf(w, "#   pip install --index-url https://%s:%s@%s/api/packages/%s/pypi/simple/ <package>\n",
			cred.Npub, token, hostPort, owner)

	case "cargo":
		fmt.Fprintf(w, "# ~/.cargo/config.toml\n")
		fmt.Fprintf(w, "[registries.grasp]\nindex = \"sparse+%s/api/packages/%s/cargo/\"\n\n", base, owner)
		fmt.Fprintf(w, "# ~/.cargo/credentials.toml (0600)\n")
		fmt.Fprintf(w, "[registries.grasp]\ntoken = \"Bearer %s\"\n", token)

	case "docker":
		fmt.Fprintf(w, "# docker login reads the token from stdin; it never appears in argv:\n")
		if showToken {
			fmt.Fprintf(w, "printf '%%s' '%s' | docker login %s -u %s --password-stdin\n", token, hostPort, cred.Npub)
		} else {
			fmt.Fprintf(w, "grasp auth token %s | docker login %s -u %s --password-stdin\n", hostPort, hostPort, cred.Npub)
		}

	case "nuget":
		fmt.Fprintf(w, "dotnet nuget add source %s/api/packages/%s/nuget/index.json \\\n", base, owner)
		fmt.Fprintf(w, "  --name grasp --username %s --password %s --store-password-in-clear-text\n", cred.Npub, token)

	default:
		return fmt.Errorf("unknown setup target %q (want npm, pypi, cargo, docker, nuget)", kind)
	}
	return nil
}

// Package localsigner detects and wraps a local Nostr signer daemon.
// Supports NIP-5F (Unix socket, 4-byte length-framed JSON-RPC) and
// NIP-55L (Linux D-Bus, org.nostr.Signer on the session bus).
package localsigner

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// Signer is the minimal interface needed for browser-bridge signing.
type Signer interface {
	GetPublicKey() (string, error)
	SignEvent(eventJSON string) (string, error)
}

// defaultNIP5FPath returns the default NIP-5F socket path.
func defaultNIP5FPath() string {
	if v := os.Getenv("NOSTR_SIGNER_SOCK"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "nostr", "signer.sock")
}

// Detect probes available local signers and returns the first working one.
// Priority: NIP-5F Unix socket → NIP-55L D-Bus.
func Detect(logger *slog.Logger) (Signer, string, error) {
	// 1. NIP-5F Unix socket
	sockPath := defaultNIP5FPath()
	if _, err := os.Stat(sockPath); err == nil {
		s := &nip5fSigner{sockPath: sockPath, logger: logger}
		if pk, err := s.GetPublicKey(); err == nil {
			logger.Info("NIP-5F signer responding", "pubkey", pk[:8]+"...")
			return s, "nip5f", nil
		} else {
			logger.Debug("NIP-5F socket exists but unresponsive", "error", err)
		}
	}

	// 2. NIP-55L D-Bus
	if s, err := newDBusSigner(logger); err == nil {
		if pk, err := s.GetPublicKey(); err == nil {
			logger.Info("NIP-55L D-Bus signer responding", "pubkey", pk[:8]+"...")
			return s, "nip55l-dbus", nil
		} else {
			logger.Debug("NIP-55L D-Bus connected but GetPublicKey failed", "error", err)
		}
	}

	return nil, "", fmt.Errorf("no local signer found (tried NIP-5F at %s, NIP-55L D-Bus)", sockPath)
}

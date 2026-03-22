//go:build linux

package localsigner

import (
	"encoding/json"
	"fmt"
	"log/slog"

	dbus "github.com/godbus/dbus/v5"
)

const (
	dbusServiceName = "org.nostr.Signer"
	dbusObjectPath  = dbus.ObjectPath("/org/nostr/signer")
	dbusInterface   = "org.nostr.Signer"
)

// dbusSigner speaks NIP-55L over the D-Bus session bus.
// Service: org.nostr.Signer, path: /org/nostr/signer
type dbusSigner struct {
	conn   *dbus.Conn
	obj    dbus.BusObject
	logger *slog.Logger
}

func newDBusSigner(logger *slog.Logger) (*dbusSigner, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect D-Bus session bus: %w", err)
	}
	obj := conn.Object(dbusServiceName, dbusObjectPath)
	return &dbusSigner{conn: conn, obj: obj, logger: logger}, nil
}

func (s *dbusSigner) GetPublicKey() (string, error) {
	var npub string
	call := s.obj.Call(dbusInterface+".GetPublicKey", 0)
	if err := call.Err; err != nil {
		return "", fmt.Errorf("D-Bus GetPublicKey: %w", err)
	}
	if err := call.Store(&npub); err != nil {
		return "", fmt.Errorf("D-Bus GetPublicKey store: %w", err)
	}
	return npub, nil
}

func (s *dbusSigner) SignEvent(eventJSON string) (string, error) {
	// NIP-55L SignEvent(eventJson, current_user, app_id) → signature string
	// The NIP-55L spec returns just the signature; we reconstruct the full
	// signed event by merging the sig back in.
	var result string
	call := s.obj.Call(dbusInterface+".SignEvent", 0,
		eventJSON, // eventJson
		"",        // current_user (empty = default key)
		"grasp-local-signer", // app_id
	)
	if err := call.Err; err != nil {
		return "", fmt.Errorf("D-Bus SignEvent: %w", err)
	}
	if err := call.Store(&result); err != nil {
		return "", fmt.Errorf("D-Bus SignEvent store: %w", err)
	}

	// result may be a full signed event JSON or just a signature string.
	// Try to parse as JSON object first.
	if json.Valid([]byte(result)) {
		var obj map[string]any
		if json.Unmarshal([]byte(result), &obj) == nil {
			if _, hasID := obj["id"]; hasID {
				// Full signed event — return as-is.
				return result, nil
			}
		}
	}

	// result is a raw signature hex — merge into the original event.
	var evt map[string]any
	if err := json.Unmarshal([]byte(eventJSON), &evt); err != nil {
		return "", fmt.Errorf("parse event for sig merge: %w", err)
	}
	evt["sig"] = result
	merged, err := json.Marshal(evt)
	if err != nil {
		return "", fmt.Errorf("marshal signed event: %w", err)
	}
	return string(merged), nil
}

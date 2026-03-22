// grasp-local-signer is a local HTTP bridge between a web browser and a
// local Nostr signer daemon (NIP-5F Unix socket or NIP-55L DBus).
//
// Run it on the same machine as your browser:
//
//	grasp-local-signer
//
// It listens on localhost:7070 (override with SIGNER_PORT) and exposes:
//
//	GET  /health  — liveness + which backend is active
//	GET  /pubkey  — returns {"pubkey":"<hex>"}
//	POST /sign    — body: JSON event, returns {"signed_event":{...}}
//
// CORS is restricted to the configured ALLOWED_ORIGIN (default: https://git.sharegap.net).
//
// Backend detection order:
//  1. NIP-5F Unix socket  ($NOSTR_SIGNER_SOCK or ~/.local/share/nostr/signer.sock)
//  2. NIP-55L D-Bus       (org.nostr.Signer on the session bus)
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/sharegap/grasp-gitea/internal/localsigner"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	port := envOr("SIGNER_PORT", "7070")
	allowedOrigin := envOr("ALLOWED_ORIGIN", "https://git.sharegap.net")

	signer, backend, err := localsigner.Detect(logger)
	if err != nil {
		logger.Error("no local signer found", "error", err)
		fmt.Fprintln(os.Stderr, "\nNo local signer found. Start one of:")
		fmt.Fprintln(os.Stderr, "  NIP-5F:  nostr-signer-sockd")
		fmt.Fprintln(os.Stderr, "  NIP-55L: nostr-signer-daemon  (or any app exposing org.nostr.Signer on D-Bus)")
		os.Exit(1)
	}
	logger.Info("local signer detected", "backend", backend)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "backend": backend})
	})
	mux.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pubkey, err := signer.GetPublicKey()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"pubkey": pubkey})
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var evtRaw json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&evtRaw); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		signed, err := signer.SignEvent(string(evtRaw))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]json.RawMessage{
			"signed_event": json.RawMessage(signed),
		})
	})

	handler := corsMiddleware(allowedOrigin, mux)

	addr := "127.0.0.1:" + port
	logger.Info("grasp-local-signer listening", "addr", addr, "allowed_origin", allowedOrigin)
	if err := http.ListenAndServe(addr, handler); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

func corsMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (origin == allowedOrigin || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

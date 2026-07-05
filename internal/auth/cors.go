// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package auth

import "net/http"

type jsonWriter func(http.ResponseWriter, int, any)

// corsMethodGuard allows the Gitea sign-in page to call the bridge-hosted
// Nostr auth endpoints when the UI is served from git.sharegap.net and the
// bridge is served from grasp.sharegap.net. The auth proof itself remains bound
// to the server-issued NIP-98 URL/nonce and is still single-use.
func corsMethodGuard(expected string, writeJSON jsonWriter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setAuthCORS(w)
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", expected+", OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != expected {
			w.Header().Set("Allow", expected+", OPTIONS")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next(w, r)
	}
}

func setAuthCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "600")
}

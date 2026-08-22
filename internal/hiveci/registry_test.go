// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
)

func TestHarborRegistryDisabledByDefault(t *testing.T) {
	registry, err := NewHarborRegistry(HarborConfig{})
	if err != nil {
		t.Fatal(err)
	}
	object := RegistryObject{Kind: RegistryObjectBlob, Digest: DigestBytes([]byte("sbom")),
		MediaType: CycloneDXJSONMediaType, Content: []byte("sbom")}
	if _, err := registry.PushByDigest(context.Background(), "sap/application", object); !errors.Is(err, ErrRegistryDisabled) {
		t.Fatalf("error=%v, want disabled", err)
	}
}

func TestHarborRegistryPushesAndVerifiesBlobAndManifestByDigest(t *testing.T) {
	var mu sync.Mutex
	stored := map[string][]byte{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			digest := path.Base(r.URL.Path)
			mu.Lock()
			_, ok := stored[digest]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/blobs/uploads/"):
			w.Header().Set("Location", server.URL+"/upload/session")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut && r.URL.Path == "/upload/session":
			content, _ := io.ReadAll(r.Body)
			digest := r.URL.Query().Get("digest")
			if digest != DigestBytes(content) {
				http.Error(w, "digest mismatch", http.StatusConflict)
				return
			}
			mu.Lock()
			stored[digest] = content
			mu.Unlock()
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
			content, _ := io.ReadAll(r.Body)
			digest := path.Base(r.URL.Path)
			if digest != DigestBytes(content) {
				http.Error(w, "digest mismatch", http.StatusConflict)
				return
			}
			mu.Lock()
			stored[digest] = content
			mu.Unlock()
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	registry, err := NewHarborRegistry(HarborConfig{Enabled: true, BaseURL: server.URL,
		AllowHTTP: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	imageRepository, err := registry.ImageRepository("sap/application")
	if err != nil || imageRepository != strings.TrimPrefix(server.URL, "http://")+"/sap/application" {
		t.Fatalf("image repository=%q err=%v", imageRepository, err)
	}
	for _, object := range []RegistryObject{
		{Kind: RegistryObjectBlob, MediaType: CycloneDXJSONMediaType, Content: []byte(`{"bomFormat":"CycloneDX"}`)},
		{Kind: RegistryObjectManifest, MediaType: OCIImageManifestV1, Content: []byte(`{"schemaVersion":2}`)},
	} {
		object.Digest = DigestBytes(object.Content)
		ref, err := registry.PushByDigest(context.Background(), "sap/application", object)
		if err != nil {
			t.Fatal(err)
		}
		if ref.Repository != "sap/application" || ref.Digest != object.Digest || ref.Size != int64(len(object.Content)) {
			t.Fatalf("reference=%+v", ref)
		}
		// Existing-object replay is verified by HEAD and does not require a tag.
		if _, err := registry.PushByDigest(context.Background(), "sap/application", object); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHarborRegistryRejectsUnexpectedStoredDigest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("f", 64))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	registry, err := NewHarborRegistry(HarborConfig{Enabled: true, BaseURL: server.URL,
		AllowHTTP: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("immutable")
	_, err = registry.PushByDigest(context.Background(), "sap/application",
		RegistryObject{Kind: RegistryObjectBlob, Digest: DigestBytes(content),
			MediaType: "application/octet-stream", Content: content})
	if !errors.Is(err, ErrRegistryConflict) {
		t.Fatalf("error=%v, want digest conflict", err)
	}
}

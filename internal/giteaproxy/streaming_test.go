// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package giteaproxy

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRequestBodyStreamsWithoutBuffering proves the proxy forwards request
// bytes as they arrive. Git pack uploads and registry blob pushes are far too
// large to buffer, and receive-pack negotiation deadlocks if the proxy waits
// for the client to finish before contacting Gitea.
func TestRequestBodyStreamsWithoutBuffering(t *testing.T) {
	firstChunk := make(chan string, 1)
	backendDone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5)
		n, err := io.ReadFull(r.Body, buf)
		if err != nil {
			t.Errorf("backend read: %v", err)
			close(firstChunk)
			return
		}
		firstChunk <- string(buf[:n])
		// Drain the rest so the client can complete.
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("done"))
		close(backendDone)
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL, FullProxy: true}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(p)
	defer front.Close()

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, front.URL+"/owner/repo.git/git-receive-pack", pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Write only the first chunk and keep the request body open.
	if _, err := pw.Write([]byte("HELLO")); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}

	select {
	case got, ok := <-firstChunk:
		if !ok {
			t.Fatal("backend failed to read the first chunk")
		}
		if got != "HELLO" {
			t.Fatalf("backend first chunk = %q, want HELLO", got)
		}
	case err := <-errCh:
		t.Fatalf("request failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("backend never saw the first chunk: the proxy buffered the request body")
	}

	// Finish the request.
	if _, err := pw.Write([]byte("WORLD")); err != nil {
		t.Fatalf("write second chunk: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}

	select {
	case resp := <-respCh:
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "done" {
			t.Fatalf("response = %d %q", resp.StatusCode, body)
		}
	case err := <-errCh:
		t.Fatalf("request failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("request never completed")
	}
	<-backendDone
}

// TestResponseBodyStreamsIncrementally proves the proxy flushes response
// bytes as the backend produces them, which git's side-band progress and
// upload-pack negotiation depend on.
func TestResponseBodyStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_, _ = w.Write([]byte("first\n"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("second\n"))
	}))
	defer backend.Close()

	p, err := New(Config{GiteaURL: backend.URL, FullProxy: true}, nil, stubInspector{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(p)
	defer front.Close()

	resp, err := http.Get(front.URL + "/owner/repo.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	lineCh := make(chan string, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			close(lineCh)
			return
		}
		lineCh <- line
	}()

	select {
	case line, ok := <-lineCh:
		if !ok || line != "first\n" {
			t.Fatalf("first line = %q (ok=%v)", line, ok)
		}
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("first response chunk never arrived: the proxy buffered the response")
	}
	close(release)

	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != "second\n" {
		t.Fatalf("rest = %q", rest)
	}
}

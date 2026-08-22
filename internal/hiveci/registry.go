// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package hiveci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

const (
	RegistryObjectManifest RegistryObjectKind = "manifest"
	RegistryObjectBlob     RegistryObjectKind = "blob"
	maxRegistryObjectBytes                    = 64 << 20
)

var (
	ErrRegistryDisabled = errors.New("OCI registry publishing is disabled")
	ErrRegistryConflict = errors.New("OCI registry digest conflict")
	registryDigestRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	registryRepoRE      = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	registryTagRE       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

type RegistryObjectKind string

// RegistryObject is content-addressed before it crosses the registry
// boundary. A local Docker image ID, mutable tag, or content-free reference
// cannot satisfy this type's validation.
type RegistryObject struct {
	Kind      RegistryObjectKind
	Digest    string
	MediaType string
	Content   []byte
}

type RegistryReference struct {
	Repository string
	Digest     string
	MediaType  string
	Size       int64
}

func (r RegistryReference) String() string { return r.Repository + "@" + r.Digest }

// OCIRegistry uploads and verifies immutable objects by digest. Implementors
// must never synthesize a tag or accept a different returned digest.
type OCIRegistry interface {
	PushByDigest(context.Context, string, RegistryObject) (RegistryReference, error)
}

func DigestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateRegistryObject(repository string, object RegistryObject) error {
	repository = strings.TrimSpace(repository)
	object.Digest = strings.ToLower(strings.TrimSpace(object.Digest))
	object.MediaType = strings.TrimSpace(object.MediaType)
	if !registryRepoRE.MatchString(repository) {
		return fmt.Errorf("valid lowercase OCI repository without a tag is required")
	}
	if object.Kind != RegistryObjectManifest && object.Kind != RegistryObjectBlob {
		return fmt.Errorf("supported OCI object kind is required")
	}
	if len(object.Content) == 0 || len(object.Content) > maxRegistryObjectBytes {
		return fmt.Errorf("OCI object content must be between 1 byte and %d bytes", maxRegistryObjectBytes)
	}
	if !registryDigestRE.MatchString(object.Digest) || object.Digest != DigestBytes(object.Content) {
		return fmt.Errorf("OCI object digest does not match its content")
	}
	if object.MediaType == "" || len(object.MediaType) > 255 || strings.ContainsAny(object.MediaType, "\x00\r\n") {
		return fmt.Errorf("valid OCI media type is required")
	}
	return nil
}

// HarborConfig is deliberately disabled by default. Credentials are read from
// files at request time so secrets do not appear in process arguments or
// serialized config. Exactly one of BearerTokenFile and
// Username/PasswordFile may be configured.
type HarborConfig struct {
	Enabled         bool
	BaseURL         string
	Username        string
	PasswordFile    string
	BearerTokenFile string
	AllowHTTP       bool
	HTTPClient      *http.Client
}

type HarborRegistry struct {
	enabled      bool
	base         *url.URL
	username     string
	passwordFile string
	tokenFile    string
	client       *http.Client
}

func NewHarborRegistry(cfg HarborConfig) (*HarborRegistry, error) {
	registry := &HarborRegistry{enabled: cfg.Enabled}
	if !cfg.Enabled {
		return registry, nil
	}
	base, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || base.Host == "" || base.Opaque != "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("valid credential-free Harbor base URL is required")
	}
	if base.Scheme != "https" && !(cfg.AllowHTTP && base.Scheme == "http") {
		return nil, fmt.Errorf("Harbor requires HTTPS")
	}
	base.Path = strings.TrimSuffix(path.Clean(base.Path), "/")
	if base.Path == "." {
		base.Path = ""
	}
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.PasswordFile = strings.TrimSpace(cfg.PasswordFile)
	cfg.BearerTokenFile = strings.TrimSpace(cfg.BearerTokenFile)
	if cfg.BearerTokenFile != "" && (cfg.Username != "" || cfg.PasswordFile != "") {
		return nil, fmt.Errorf("configure either Harbor bearer token or basic authentication")
	}
	if (cfg.Username == "") != (cfg.PasswordFile == "") {
		return nil, fmt.Errorf("Harbor username and password file must be configured together")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	priorRedirect := client.CheckRedirect
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != base.Scheme || !strings.EqualFold(req.URL.Host, base.Host) {
			return fmt.Errorf("Harbor redirect changed origin")
		}
		if priorRedirect != nil {
			return priorRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many Harbor redirects")
		}
		return nil
	}
	registry.base = base
	registry.username = cfg.Username
	registry.passwordFile = cfg.PasswordFile
	registry.tokenFile = cfg.BearerTokenFile
	registry.client = &clientCopy
	return registry, nil
}

func (r *HarborRegistry) PushByDigest(ctx context.Context, repository string, object RegistryObject) (RegistryReference, error) {
	if r == nil || !r.enabled {
		return RegistryReference{}, ErrRegistryDisabled
	}
	if err := validateRegistryObject(repository, object); err != nil {
		return RegistryReference{}, err
	}
	repository = strings.TrimSpace(repository)
	object.Digest = strings.ToLower(strings.TrimSpace(object.Digest))
	exists, err := r.head(ctx, repository, object)
	if err != nil {
		return RegistryReference{}, err
	}
	if !exists {
		if object.Kind == RegistryObjectManifest {
			if err := r.putManifest(ctx, repository, object); err != nil {
				return RegistryReference{}, err
			}
		} else if err := r.putBlob(ctx, repository, object); err != nil {
			return RegistryReference{}, err
		}
	}
	exists, err = r.head(ctx, repository, object)
	if err != nil {
		return RegistryReference{}, err
	}
	if !exists {
		return RegistryReference{}, fmt.Errorf("Harbor object is not readable after upload")
	}
	return RegistryReference{Repository: repository, Digest: object.Digest,
		MediaType: object.MediaType, Size: int64(len(object.Content))}, nil
}

// ImageRepository returns the credential-free repository name consumers use
// to pull an artifact. The registry API repository remains a path, while OCI
// clients (including Bahia) require the Harbor authority as part of image_repo.
func (r *HarborRegistry) ImageRepository(repository string) (string, error) {
	if r == nil || !r.enabled || r.base == nil {
		return "", ErrRegistryDisabled
	}
	repository = strings.TrimSpace(repository)
	if !registryRepoRE.MatchString(repository) {
		return "", fmt.Errorf("valid lowercase OCI repository without a tag is required")
	}
	imageRepository := r.base.Host + "/" + repository
	if !validImageRepository(imageRepository) {
		return "", fmt.Errorf("Harbor repository does not form a valid pull reference")
	}
	return imageRepository, nil
}

func (r *HarborRegistry) objectURL(repository string, object RegistryObject) *url.URL {
	u := *r.base
	segments := strings.Split(repository, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	resource := "blobs"
	if object.Kind == RegistryObjectManifest {
		resource = "manifests"
	}
	u.Path = strings.TrimSuffix(r.base.Path, "/") + "/v2/" + strings.Join(segments, "/") +
		"/" + resource + "/" + url.PathEscape(object.Digest)
	return &u
}

func (r *HarborRegistry) head(ctx context.Context, repository string, object RegistryObject) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.objectURL(repository, object).String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", object.MediaType)
	if err := r.authorize(req); err != nil {
		return false, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("check Harbor object: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		if got := strings.ToLower(strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))); got != object.Digest {
			return false, fmt.Errorf("%w: Harbor returned unexpected digest", ErrRegistryConflict)
		}
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusConflict:
		return false, fmt.Errorf("%w: Harbor rejected digest", ErrRegistryConflict)
	default:
		return false, fmt.Errorf("check Harbor object: unexpected HTTP status %d", resp.StatusCode)
	}
}

func (r *HarborRegistry) putManifest(ctx context.Context, repository string, object RegistryObject) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, r.objectURL(repository, object).String(),
		bytes.NewReader(object.Content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", object.MediaType)
	if err := r.authorize(req); err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("upload Harbor manifest: %w", err)
	}
	defer resp.Body.Close()
	return checkUploadResponse("manifest", resp, object.Digest)
}

func (r *HarborRegistry) putBlob(ctx context.Context, repository string, object RegistryObject) error {
	start := *r.base
	segments := strings.Split(repository, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	start.Path = strings.TrimSuffix(r.base.Path, "/") + "/v2/" + strings.Join(segments, "/") + "/blobs/uploads/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, start.String(), nil)
	if err != nil {
		return err
	}
	if err := r.authorize(req); err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("start Harbor blob upload: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusConflict {
			return fmt.Errorf("%w: Harbor rejected blob upload", ErrRegistryConflict)
		}
		return fmt.Errorf("start Harbor blob upload: unexpected HTTP status %d", resp.StatusCode)
	}
	location := strings.TrimSpace(resp.Header.Get("Location"))
	uploadURL, err := r.base.Parse(location)
	if err != nil || location == "" || uploadURL.Scheme != r.base.Scheme ||
		!strings.EqualFold(uploadURL.Host, r.base.Host) {
		return fmt.Errorf("Harbor returned invalid upload location")
	}
	query := uploadURL.Query()
	query.Set("digest", object.Digest)
	uploadURL.RawQuery = query.Encode()
	req, err = http.NewRequestWithContext(ctx, http.MethodPut, uploadURL.String(), bytes.NewReader(object.Content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", object.MediaType)
	if err := r.authorize(req); err != nil {
		return err
	}
	resp, err = r.client.Do(req)
	if err != nil {
		return fmt.Errorf("upload Harbor blob: %w", err)
	}
	defer resp.Body.Close()
	return checkUploadResponse("blob", resp, object.Digest)
}

func checkUploadResponse(kind string, resp *http.Response, wantDigest string) error {
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("%w: Harbor rejected %s digest", ErrRegistryConflict, kind)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("upload Harbor %s: unexpected HTTP status %d", kind, resp.StatusCode)
	}
	if got := strings.ToLower(strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))); got != wantDigest {
		return fmt.Errorf("%w: Harbor stored unexpected %s digest", ErrRegistryConflict, kind)
	}
	return nil
}

func (r *HarborRegistry) authorize(req *http.Request) error {
	if r.tokenFile != "" {
		token, err := readCredentialFile(r.tokenFile)
		if err != nil {
			return fmt.Errorf("read Harbor bearer credential: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	if r.passwordFile != "" {
		password, err := readCredentialFile(r.passwordFile)
		if err != nil {
			return fmt.Errorf("read Harbor basic credential: %w", err)
		}
		req.SetBasicAuth(r.username, password)
	}
	return nil
}

func readCredentialFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64<<10))
	if err != nil {
		return "", err
	}
	credential := strings.TrimSpace(string(content))
	if credential == "" || strings.ContainsAny(credential, "\x00\r\n") {
		return "", fmt.Errorf("credential file is empty or malformed")
	}
	return credential, nil
}

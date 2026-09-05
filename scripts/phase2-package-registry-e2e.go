//go:build ignore

// Phase 2C deployment E2E driver. It exercises every package family served by
// Gitea 1.24.6 through the full TLS/nginx/bridge/Gitea stack.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fiatjaf.com/nostr"
)

const publicURL = "https://grasp.test"

type minted struct{ ID, Token string }
type fixture struct {
	name, writeMethod, writePath, readPath string
	publish                                func(*runner, string) error
}
type runner struct {
	client              *http.Client
	login               string
	full, read, revoked minted
	root                string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "phase2 package E2E FAILED:", err)
		os.Exit(1)
	}
}

func run() error {
	r := &runner{client: localClient(), root: os.Getenv("E2E_REPO_ROOT")}
	if r.root == "" {
		return fmt.Errorf("E2E_REPO_ROOT is required")
	}
	key := nostr.Generate()
	login, err := establishIdentity(r.client, key)
	if err != nil {
		return err
	}
	r.login = login
	if r.full, err = mintToken(r.client, key, "phase2-full", []string{"packages:read", "packages:write"}); err != nil {
		return err
	}
	if r.read, err = mintToken(r.client, key, "phase2-read", []string{"packages:read"}); err != nil {
		return err
	}
	if r.revoked, err = mintToken(r.client, key, "phase2-revoked", []string{"packages:read", "packages:write"}); err != nil {
		return err
	}

	fixtures := packageFixtures()
	fmt.Printf("[catalog] Gitea 1.24.6: %d Phase 2C families (Arch, Chef, and Helm included; Terraform absent)\n", len(fixtures))
	for _, f := range fixtures {
		fmt.Printf("[%s] publish and download\n", f.name)
		if err := f.publish(r, r.full.Token); err != nil {
			return fmt.Errorf("%s publish: %w", f.name, err)
		}
		if _, err := r.request(http.MethodGet, f.readPath, nil, r.bridgeAuth(f.name, r.full.Token), http.StatusOK); err != nil {
			return fmt.Errorf("%s download: %w", f.name, err)
		}

		fmt.Printf("[%s] insufficient scope and 8 MiB streaming upload\n", f.name)
		if _, err := r.request(f.writeMethod, f.writePath, strings.NewReader("denied"), r.bridgeAuth(f.name, r.read.Token), http.StatusForbidden); err != nil {
			return fmt.Errorf("%s insufficient scope: %w", f.name, err)
		}
		status, err := r.requestAny(f.writeMethod, f.writePath, io.LimitReader(zeroReader{}, 8<<20), r.bridgeAuth(f.name, r.full.Token))
		if err != nil {
			return fmt.Errorf("%s large upload: %w", f.name, err)
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusRequestEntityTooLarge || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
			return fmt.Errorf("%s large upload status %d proves auth/proxy rejection", f.name, status)
		}
	}

	if err := revokeToken(r.client, key, r.revoked.ID); err != nil {
		return err
	}
	for _, f := range fixtures {
		if _, err := r.request(http.MethodGet, f.readPath, nil, r.bridgeAuth(f.name, r.revoked.Token), http.StatusUnauthorized); err != nil {
			return fmt.Errorf("%s revocation: %w", f.name, err)
		}
	}
	if _, err := r.request(http.MethodGet, "/api/packages/"+url.PathEscape(r.login)+"/unknown/file", nil, "Bearer "+r.full.Token, http.StatusForbidden); err != nil {
		return fmt.Errorf("unknown family: %w", err)
	}
	fmt.Println("phase2 package registry E2E PASSED (Docker excluded: deployed registry JWT revocation bound is 24h)")
	return nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func packageFixtures() []fixture {
	owner := "{owner}"
	return []fixture{
		{"alpine", http.MethodPut, "/api/packages/" + owner + "/alpine/v3.20/main-large", "/api/packages/" + owner + "/alpine/v3.20/main/x86_64/gitea-test-1.4.1-r3.apk", publishAlpine},
		{"arch", http.MethodPut, "/api/packages/" + owner + "/arch/large", "/api/packages/" + owner + "/arch/main/aarch64/gitea-test-1.4.1-r3-aarch64.pkg.tar.gz", publishArch},
		{"chef", http.MethodPost, "/api/packages/" + owner + "/chef/api/v1/cookbooks", "/api/packages/" + owner + "/chef/api/v1/cookbooks/phase2/versions/1.0.1/download", publishChef},
		{"conan", http.MethodPut, "/api/packages/" + owner + "/conan/v2/conans/large/1/usr/stable/revisions/r/files/blob", "/api/packages/" + owner + "/conan/v2/conans/phase2/1.0/usr/stable/revisions/r1/files/conanfile.py", publishConan},
		{"conda", http.MethodPut, "/api/packages/" + owner + "/conda/large-1.0.tar.bz2", "/api/packages/" + owner + "/conda/noarch/phase2-1.0-0.tar.bz2", publishConda},
		{"cran", http.MethodPut, "/api/packages/" + owner + "/cran/src", "/api/packages/" + owner + "/cran/src/contrib/phase2.cran_1.0.3.tar.gz", publishCRAN},
		{"debian", http.MethodPut, "/api/packages/" + owner + "/debian/pool/large/main/upload", "/api/packages/" + owner + "/debian/pool/stable/main/phase2_1.0.3_amd64.deb", publishDebian},
		{"go", http.MethodPut, "/api/packages/" + owner + "/go/upload", "/api/packages/" + owner + "/go/example.invalid/phase2/@v/v1.0.0.zip", publishGo},
		{"helm", http.MethodPost, "/api/packages/" + owner + "/helm/api/charts", "/api/packages/" + owner + "/helm/phase2-chart-1.0.3.tgz", publishHelm},
		{"nuget", http.MethodPut, "/api/packages/" + owner + "/nuget/", "/api/packages/" + owner + "/nuget/package/phase2.nuget/1.0.3/phase2.nuget.1.0.3.nupkg", publishNuGet},
		{"pub", http.MethodPost, "/api/packages/" + owner + "/pub/api/packages/versions/new/upload", "/api/packages/" + owner + "/pub/api/packages/phase2_pub/files/1.0.1", publishPub},
		{"rpm", http.MethodPut, "/api/packages/" + owner + "/rpm/large/upload", "/api/packages/" + owner + "/rpm/stable/package/gitea-test/1.0.2-1/x86_64", publishRPM},
		{"rubygems", http.MethodPost, "/api/packages/" + owner + "/rubygems/api/v1/gems", "/api/packages/" + owner + "/rubygems/gems/phase2-gem-1.0.5.gem", publishRubyGems},
		{"swift", http.MethodPut, "/api/packages/" + owner + "/swift/phase2/kit/1.0.3", "/api/packages/" + owner + "/swift/phase2/kit/1.0.3.zip", publishSwift},
		{"vagrant", http.MethodPut, "/api/packages/" + owner + "/vagrant/large/1.0.0/virtualbox.box", "/api/packages/" + owner + "/vagrant/phase2_box/1.0.1/virtualbox.box", publishVagrant},
	}
}

func (r *runner) path(p string) string {
	return strings.ReplaceAll(p, "{owner}", url.PathEscape(r.login))
}
func (r *runner) bridgeAuth(family, token string) string {
	if family == "nuget" {
		return "NuGet " + token
	}
	if family == "pub" || family == "vagrant" {
		return "Bearer " + token
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(r.login+":"+token))
}
func (r *runner) request(method, path string, body io.Reader, authorization string, want int) ([]byte, error) {
	status, data, err := r.do(method, r.path(path), body, authorization, "")
	if err != nil {
		return nil, err
	}
	if status != want {
		return nil, fmt.Errorf("%s %s = %d: %s", method, r.path(path), status, clip(data))
	}
	return data, nil
}
func (r *runner) requestAny(method, path string, body io.Reader, authorization string) (int, error) {
	status, _, err := r.do(method, r.path(path), body, authorization, "application/octet-stream")
	return status, err
}
func (r *runner) do(method, path string, body io.Reader, authorization, contentType string) (int, []byte, error) {
	req, err := http.NewRequest(method, publicURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	if strings.HasPrefix(authorization, "NuGet ") {
		req.Header.Set("X-NuGet-ApiKey", strings.TrimPrefix(authorization, "NuGet "))
	} else if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if strings.Contains(path, "/swift/") {
		if method == http.MethodPut {
			req.Header.Set("Accept", "application/vnd.swift.registry.v1+json")
		} else if strings.HasSuffix(path, ".zip") {
			req.Header.Set("Accept", "application/vnd.swift.registry.v1+zip")
		}
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}
func clip(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return strings.TrimSpace(string(b))
}

func establishIdentity(c *http.Client, key nostr.SecretKey) (string, error) {
	var ch struct{ Nonce, URL string }
	if err := jsonCall(c, http.MethodPost, "/auth/nip07/challenge", map[string]string{"redirect_uri": "/"}, "", http.StatusOK, &ch); err != nil {
		return "", err
	}
	ev := nostr.Event{Kind: 27235, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"u", ch.URL}, {"method", "POST"}, {"nonce", ch.Nonce}}}
	if err := ev.Sign(key); err != nil {
		return "", err
	}
	var out struct {
		Identity struct {
			GiteaUser string `json:"gitea_user"`
		} `json:"identity"`
	}
	if err := jsonCall(c, http.MethodPost, "/auth/nip07/verify", map[string]any{"signed_event": ev}, "", http.StatusOK, &out); err != nil {
		return "", err
	}
	if out.Identity.GiteaUser == "" {
		return "", fmt.Errorf("identity returned no Gitea user")
	}
	return out.Identity.GiteaUser, nil
}
func mintToken(c *http.Client, key nostr.SecretKey, name string, scopes []string) (minted, error) {
	body, _ := json.Marshal(map[string]any{"name": name, "scopes": scopes})
	auth, err := nip98(key, publicURL+"/auth/token", http.MethodPost, body)
	if err != nil {
		return minted{}, err
	}
	var out minted
	err = jsonCallRaw(c, http.MethodPost, "/auth/token", body, auth, http.StatusCreated, &out)
	return out, err
}
func revokeToken(c *http.Client, key nostr.SecretKey, id string) error {
	path := "/auth/tokens/" + url.PathEscape(id)
	auth, err := nip98(key, publicURL+path, http.MethodDelete, nil)
	if err != nil {
		return err
	}
	return jsonCallRaw(c, http.MethodDelete, path, nil, auth, http.StatusNoContent, nil)
}
func nip98(key nostr.SecretKey, target, method string, body []byte) (string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	tags := nostr.Tags{{"u", target}, {"method", method}, {"nonce", hex.EncodeToString(nonce)}}
	if len(body) > 0 {
		h := sha256.Sum256(body)
		tags = append(tags, nostr.Tag{"payload", hex.EncodeToString(h[:])})
	}
	ev := nostr.Event{Kind: 27235, CreatedAt: nostr.Timestamp(time.Now().Unix()), Tags: tags}
	if err := ev.Sign(key); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(ev)
	return "Nostr " + base64.StdEncoding.EncodeToString(raw), nil
}
func jsonCall(c *http.Client, m, p string, in any, auth string, want int, out any) error {
	var b []byte
	if in != nil {
		b, _ = json.Marshal(in)
	}
	return jsonCallRaw(c, m, p, b, auth, want, out)
}
func jsonCallRaw(c *http.Client, m, p string, b []byte, auth string, want int, out any) error {
	req, _ := http.NewRequest(m, publicURL+p, bytes.NewReader(b))
	if len(b) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s = %d: %s", m, p, resp.StatusCode, clip(raw))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}
func localClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, "127.0.0.1:443")
	}}, Timeout: 2 * time.Minute}
}

func publishAlpine(r *runner, tok string) error {
	b, err := os.ReadFile(filepath.Join(r.root, "scripts/testdata/phase2/alpine.apk"))
	if err != nil {
		return err
	}
	_, err = r.request(http.MethodPut, "/api/packages/{owner}/alpine/v3.20/main", bytes.NewReader(b), r.bridgeAuth("alpine", tok), http.StatusCreated)
	return err
}
func publishRPM(r *runner, tok string) error {
	b, err := os.ReadFile(filepath.Join(r.root, "scripts/testdata/phase2/rpm.rpm"))
	if err != nil {
		return err
	}
	_, err = r.request(http.MethodPut, "/api/packages/{owner}/rpm/stable/upload", bytes.NewReader(b), r.bridgeAuth("rpm", tok), http.StatusCreated)
	return err
}
func publishArch(r *runner, tok string) error {
	info := []byte("pkgname = gitea-test\npkgbase = gitea-test\npkgver = 1.4.1-r3\npkgdesc = Description\nbuilddate = 1678834800\nsize = 8\narch = aarch64\nlicense = MIT")
	b := tarGz(map[string][]byte{".PKGINFO": info, "opt/file": []byte("test")})
	_, err := r.request(http.MethodPut, "/api/packages/{owner}/arch/main", bytes.NewReader(b), r.bridgeAuth("arch", tok), http.StatusCreated)
	return err
}
func publishChef(r *runner, tok string) error {
	pkg := tarGz(map[string][]byte{"phase2/metadata.json": []byte(`{"name":"phase2","version":"1.0.1","description":"Phase 2","maintainer":"grasp"}`)})
	body, ct := multipartBody("tarball", "1.0.1.tar.gz", pkg, map[string]string{})
	status, data, err := r.do(http.MethodPost, r.path("/api/packages/{owner}/chef/api/v1/cookbooks"), bytes.NewReader(body), r.bridgeAuth("chef", tok), ct)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("status %d: %s", status, clip(data))
	}
	return nil
}
func publishConan(r *runner, tok string) error {
	exchange := "/api/packages/{owner}/conan/v2/users/authenticate"
	raw, err := r.request(http.MethodGet, exchange, nil, r.bridgeAuth("conan", tok), http.StatusOK)
	if err != nil {
		return err
	}
	if string(raw) != tok {
		return fmt.Errorf("exchange returned non-bridge token")
	}
	path := "/api/packages/{owner}/conan/v2/conans/phase2/1.0/usr/stable/revisions/r1/files/conanfile.py"
	_, err = r.request(http.MethodPut, path, strings.NewReader("from conans import ConanFile\n"), "Bearer "+string(raw), http.StatusCreated)
	return err
}
func publishConda(r *runner, tok string) error {
	raw := tarBytes(map[string][]byte{"info/index.json": []byte(`{"name":"phase2","version":"1.0","subdir":"noarch","build":"0"}`)})
	cmd := exec.Command("bzip2", "-c")
	cmd.Stdin = bytes.NewReader(raw)
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	_, err = r.request(http.MethodPut, "/api/packages/{owner}/conda/phase2-1.0.tar.bz2", bytes.NewReader(b), r.bridgeAuth("conda", tok), http.StatusCreated)
	return err
}
func publishCRAN(r *runner, tok string) error {
	desc := []byte("Package: phase2.cran\nVersion: 1.0.3\nDescription: Phase 2\nLicense: MIT\nAuthor: grasp\n")
	b := tarGz(map[string][]byte{"phase2.cran/DESCRIPTION": desc})
	_, err := r.request(http.MethodPut, "/api/packages/{owner}/cran/src", bytes.NewReader(b), r.bridgeAuth("cran", tok), http.StatusCreated)
	return err
}
func publishDebian(r *runner, tok string) error {
	control := tarGz(map[string][]byte{"control": []byte("Package: phase2\nVersion: 1.0.3\nArchitecture: amd64\nDescription: Phase 2\n")})
	b := arArchive("control.tar.gz", control)
	_, err := r.request(http.MethodPut, "/api/packages/{owner}/debian/pool/stable/main/upload", bytes.NewReader(b), r.bridgeAuth("debian", tok), http.StatusCreated)
	return err
}
func publishGo(r *runner, tok string) error {
	name := "example.invalid/phase2@v1.0.0/go.mod"
	b := zipBytes(map[string][]byte{name: []byte("module example.invalid/phase2\n")})
	_, err := r.request(http.MethodPut, "/api/packages/{owner}/go/upload", bytes.NewReader(b), r.bridgeAuth("go", tok), http.StatusCreated)
	return err
}
func publishHelm(r *runner, tok string) error {
	chart := []byte("apiVersion: v2\nname: phase2-chart\nversion: 1.0.3\ndescription: Phase 2\n")
	b := tarGz(map[string][]byte{"phase2-chart/Chart.yaml": chart})
	status, data, err := r.do(http.MethodPost, r.path("/api/packages/{owner}/helm/api/charts"), bytes.NewReader(b), r.bridgeAuth("helm", tok), "application/gzip")
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("status %d: %s", status, clip(data))
	}
	return nil
}
func publishNuGet(r *runner, tok string) error {
	nuspec := []byte(`<?xml version="1.0"?><package><metadata><id>phase2.nuget</id><version>1.0.3</version><authors>grasp</authors><description>Phase 2</description></metadata></package>`)
	b := zipBytes(map[string][]byte{"package.nuspec": nuspec})
	_, err := r.request(http.MethodPut, "/api/packages/{owner}/nuget/", bytes.NewReader(b), r.bridgeAuth("nuget", tok), http.StatusCreated)
	return err
}
func publishPub(r *runner, tok string) error {
	raw, err := r.request(http.MethodGet, "/api/packages/{owner}/pub/api/packages/versions/new", nil, r.bridgeAuth("pub", tok), http.StatusOK)
	if err != nil {
		return err
	}
	var up struct {
		URL string `json:"url"`
	}
	if err = json.Unmarshal(raw, &up); err != nil {
		return err
	}
	pkg := tarGz(map[string][]byte{"pubspec.yaml": []byte("name: phase2_pub\nversion: 1.0.1\ndescription: Phase 2\n")})
	body, ct := multipartBody("file", "phase2.tar.gz", pkg, nil)
	req, _ := http.NewRequest(http.MethodPost, up.URL, bytes.NewReader(body))
	req.Header.Set("Authorization", r.bridgeAuth("pub", tok))
	req.Header.Set("Content-Type", ct)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("upload status %d: %s", resp.StatusCode, clip(data))
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("upload returned no finalize location")
	}
	if strings.HasPrefix(loc, publicURL) {
		loc = strings.TrimPrefix(loc, publicURL)
	}
	_, err = r.request(http.MethodGet, loc, nil, r.bridgeAuth("pub", tok), http.StatusOK)
	return err
}
func publishRubyGems(r *runner, tok string) error {
	b := rubyGem("phase2-gem", "1.0.5")
	status, data, err := r.do(http.MethodPost, r.path("/api/packages/{owner}/rubygems/api/v1/gems"), bytes.NewReader(b), r.bridgeAuth("rubygems", tok), "application/octet-stream")
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("status %d: %s", status, clip(data))
	}
	return nil
}
func publishSwift(r *runner, tok string) error {
	z := zipBytes(map[string][]byte{"Package.swift": []byte("// swift-tools-version:5.7\n")})
	meta := `{"name":"kit","version":"1.0.3","description":"Phase 2","codeRepository":"https://example.invalid/phase2"}`
	body, ct := multipartBody("source-archive", "source.zip", z, map[string]string{"metadata": meta})
	status, data, err := r.do(http.MethodPut, r.path("/api/packages/{owner}/swift/phase2/kit/1.0.3"), bytes.NewReader(body), r.bridgeAuth("swift", tok), ct)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("status %d: %s", status, clip(data))
	}
	return nil
}
func publishVagrant(r *runner, tok string) error {
	b := tarGz(map[string][]byte{"info.json": []byte(`{"description":"Phase 2"}`)})
	_, err := r.request(http.MethodPut, "/api/packages/{owner}/vagrant/phase2_box/1.0.1/virtualbox.box", bytes.NewReader(b), r.bridgeAuth("vagrant", tok), http.StatusCreated)
	return err
}

func tarBytes(files map[string][]byte) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for n, d := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(d))})
		_, _ = tw.Write(d)
	}
	_ = tw.Close()
	return b.Bytes()
}
func tarGz(files map[string][]byte) []byte {
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	tw := tar.NewWriter(gw)
	for n, d := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(d))})
		_, _ = tw.Write(d)
	}
	_ = tw.Close()
	_ = gw.Close()
	return b.Bytes()
}
func zipBytes(files map[string][]byte) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for n, d := range files {
		w, _ := zw.Create(n)
		_, _ = w.Write(d)
	}
	_ = zw.Close()
	return b.Bytes()
}
func multipartBody(field, name string, data []byte, values map[string]string) ([]byte, string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	p, _ := mw.CreateFormFile(field, name)
	_, _ = p.Write(data)
	for k, v := range values {
		_ = mw.WriteField(k, v)
	}
	_ = mw.Close()
	return b.Bytes(), mw.FormDataContentType()
}
func arArchive(name string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", time.Now().Unix(), 0, 0, 0600, len(data))
	b.WriteString(header)
	b.Write(data)
	if len(data)%2 != 0 {
		b.WriteByte('\n')
	}
	return b.Bytes()
}

type gemFile struct {
	Name string
	Data []byte
}

func gemTar(fs []gemFile) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range fs {
		_ = tw.WriteHeader(&tar.Header{Name: f.Name, Mode: 0644, Size: int64(len(f.Data))})
		_, _ = tw.Write(f.Data)
	}
	_ = tw.Close()
	return b.Bytes()
}
func gemGz(d []byte) []byte {
	var b bytes.Buffer
	gw, _ := gzip.NewWriterLevel(&b, gzip.NoCompression)
	_, _ = gw.Write(d)
	_ = gw.Close()
	return b.Bytes()
}
func rubyGem(name, version string) []byte {
	meta := gemGz([]byte(fmt.Sprintf("--- !ruby/object:Gem::Specification\nname: %s\nversion: !ruby/object:Gem::Version\n  version: %s\nplatform: ruby\nauthors:\n- grasp\ndescription: Phase 2\nemail: test@example.invalid\nfiles:\n- lib/phase2.rb\nhomepage: https://example.invalid\nlicenses:\n- MIT\nrequire_paths:\n- lib\nrequired_ruby_version: !ruby/object:Gem::Requirement\n  requirements: []\nrequired_rubygems_version: !ruby/object:Gem::Requirement\n  requirements: []\nrubygems_version: 2.7.6\nspecification_version: 4\nsummary: Phase 2\n", name, version)))
	data := gemGz(gemTar([]gemFile{{"lib/phase2.rb", []byte("class Phase2; end\n")}}))
	checks := gemGz([]byte(fmt.Sprintf("---\nSHA256:\n  metadata.gz: %x\n  data.tar.gz: %x\nSHA512:\n  metadata.gz: %x\n  data.tar.gz: %x\n", sha256.Sum256(meta), sha256.Sum256(data), sha512.Sum512(meta), sha512.Sum512(data))))
	return gemTar([]gemFile{{"data.tar.gz", data}, {"metadata.gz", meta}, {"checksums.yaml.gz", checks}})
}

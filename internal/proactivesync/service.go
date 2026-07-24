package proactivesync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
	"github.com/sharegap/grasp-gitea/internal/store"
)

const (
	DefaultSyncInterval = time.Hour
	relayQueryTimeout   = 5 * time.Second
	stateQueryLimit     = 200
	prQueryLimit        = 500
)

var (
	validRef          = regexp.MustCompile(`^refs/(heads|tags)/[a-zA-Z0-9][a-zA-Z0-9._/\-]*$`)
	validHex          = regexp.MustCompile(`^[0-9a-f]{4,64}$`)
	validNostrEventID = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// OrgResolver looks up the Gitea org name for a given npub/repoID.
// Returns empty string if not found.
type OrgResolver interface {
	GetMapping(ctx context.Context, npub string, repoID string) (store.Mapping, error)
}

type MappingLister interface {
	ListMappings(ctx context.Context) ([]store.Mapping, error)
}

type gitRunner interface {
	ObjectExists(ctx context.Context, repoPath string, sha string) (bool, error)
	UpdateRef(ctx context.Context, repoPath string, ref string, sha string) error
	SetSymbolicHEAD(ctx context.Context, repoPath string, ref string) error
	ListRefs(ctx context.Context, repoPath string, prefix string) ([]string, error)
	DeleteRef(ctx context.Context, repoPath string, ref string) error
	Fetch(ctx context.Context, repoPath string, remoteURL string, refspecs []string) error
}

type relayQueryFunc func(ctx context.Context, relayURL string, filter nostr.Filter) ([]*nostr.Event, error)

type syncTicker interface {
	C() <-chan time.Time
	Stop()
}

type realTicker struct {
	*time.Ticker
}

func (t realTicker) C() <-chan time.Time { return t.Ticker.C }

type Service struct {
	repositoriesDir string
	orgResolver     OrgResolver
	mappingLister   MappingLister
	logger          *slog.Logger
	git             gitRunner
	queryRelay      relayQueryFunc
	newTicker       func(time.Duration) syncTicker
}

func New(repositoriesDir string, orgResolver OrgResolver, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		repositoriesDir: repositoriesDir,
		orgResolver:     orgResolver,
		logger:          logger,
		git:             execGitRunner{},
		queryRelay:      queryRelaySync,
		newTicker: func(interval time.Duration) syncTicker {
			return realTicker{Ticker: time.NewTicker(interval)}
		},
	}
	if lister, ok := orgResolver.(MappingLister); ok {
		s.mappingLister = lister
	}
	return s
}

func (s *Service) HandleStateEvent(ctx context.Context, ev *nostr.Event) error {
	if ev == nil || ev.Kind != nostr.KindRepositoryState {
		return nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return err
	}

	repoID := tagValue(ev.Tags, "d")
	if repoID == "" {
		return fmt.Errorf("state event missing d tag")
	}

	lookupPubkey := ev.PubKey.Hex()
	if ownerPubkey := tagValue(ev.Tags, "p"); ownerPubkey != "" {
		lookupPubkey = ownerPubkey
	}
	lookupPK, err := nostr.PubKeyFromHex(lookupPubkey)
	if err != nil {
		return fmt.Errorf("invalid pubkey: %w", err)
	}
	npub := nip19.EncodeNpub(lookupPK)

	// Look up the actual Gitea org name from the store, since repos are
	// created under the NIP-05-resolved org name, not the raw npub.
	orgName := npub
	repoName := repoID
	if s.orgResolver != nil {
		mapping, lookupErr := s.orgResolver.GetMapping(ctx, npub, repoID)
		if lookupErr != nil {
			// Repo not provisioned yet; skip silently.
			return nil
		}
		if mapping.Owner != "" {
			orgName = mapping.Owner
		}
		if mapping.RepoName != "" {
			repoName = mapping.RepoName
		}
	}

	repoPath := filepath.Join(s.repositoriesDir, orgName, repoName+".git")
	if st, err := os.Stat(repoPath); err != nil || !st.IsDir() {
		return nil
	}

	return s.applyStateEvent(ctx, repoPath, ev)
}

// Run starts the scheduled GRASP-02 backfill worker. It intentionally waits for
// the first tick instead of running immediately, so startup remains bounded and
// tests can deterministically drive the tick.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	interval = NormalizeSyncInterval(interval)
	ticker := s.newTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			if err := s.SyncOnce(ctx); err != nil {
				s.logger.Warn("proactive sync scheduled tick failed", "error", err)
			}
		}
	}
}

// NormalizeSyncInterval enforces GRASP-02's at-least-hourly cadence. Operators
// may configure a more frequent interval, but values above 1h are clamped.
func NormalizeSyncInterval(interval time.Duration) time.Duration {
	if interval <= 0 || interval > DefaultSyncInterval {
		return DefaultSyncInterval
	}
	return interval
}

// SyncOnce performs one historic backfill pass across all accepted repository
// mappings. For each cached accepted announcement, it queries the announcement's
// relay set for state and PR events, fetches missing git objects from clone
// servers, applies state refs, and materialises PR tips under refs/nostr/<id>.
func (s *Service) SyncOnce(ctx context.Context) error {
	if s.mappingLister == nil {
		return nil
	}
	mappings, err := s.mappingLister.ListMappings(ctx)
	if err != nil {
		return fmt.Errorf("list mappings: %w", err)
	}
	var errs []string
	for _, mapping := range mappings {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.syncMapping(ctx, mapping); err != nil {
			errs = append(errs, fmt.Sprintf("%s/%s: %v", mapping.Owner, mapping.RepoID, err))
			s.logger.Warn("proactive sync mapping failed", "owner", mapping.Owner, "repo_id", mapping.RepoID, "error", err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Service) syncMapping(ctx context.Context, mapping store.Mapping) error {
	announcement, err := cachedAnnouncement(mapping)
	if err != nil {
		return err
	}
	cloneURLs := announcementCloneURLs(mapping, announcement)
	relayURLs := announcementRelayURLs(announcement)
	if len(cloneURLs) == 0 && len(relayURLs) == 0 {
		return nil
	}

	repoPath := repoPathForMapping(s.repositoriesDir, mapping)
	if st, err := os.Stat(repoPath); err != nil || !st.IsDir() {
		return nil
	}

	if len(relayURLs) > 0 {
		latestState := s.fetchLatestStateEvent(ctx, mapping, relayURLs)
		if latestState != nil {
			state := nip34.ParseRepositoryState(*latestState)
			if err := s.fetchMissingStateObjects(ctx, repoPath, cloneURLs, state); err != nil {
				s.logger.Warn("proactive sync state object fetch failed", "repo", repoPath, "error", err)
			}
			if err := s.applyStateEvent(ctx, repoPath, latestState); err != nil {
				s.logger.Warn("proactive sync state ref reconciliation failed", "repo", repoPath, "event", latestState.ID, "error", err)
			}
		}

		prEvents := s.fetchPREvents(ctx, mapping, relayURLs)
		for _, ev := range prEvents {
			if err := s.fetchPRTip(ctx, repoPath, ev); err != nil {
				s.logger.Warn("proactive sync PR tip fetch failed", "repo", repoPath, "event", ev.ID.Hex(), "error", err)
			}
		}
	}
	return nil
}

func (s *Service) fetchLatestStateEvent(ctx context.Context, mapping store.Mapping, relayURLs []string) *nostr.Event {
	authorPK, err := nostr.PubKeyFromHex(mapping.Pubkey)
	if err != nil {
		s.logger.Warn("proactive sync invalid mapping pubkey", "repo_id", mapping.RepoID, "error", err)
		return nil
	}
	filter := nostr.Filter{
		Kinds:   []nostr.Kind{relay.KindRepositoryState},
		Authors: []nostr.PubKey{authorPK},
		Tags:    nostr.TagMap{"d": []string{mapping.RepoID}},
		Limit:   stateQueryLimit,
	}
	var latest *nostr.Event
	for _, relayURL := range relayURLs {
		events, err := s.queryRelayHistory(ctx, relayURL, filter, stateQueryLimit)
		if err != nil {
			s.logger.Warn("proactive sync state relay query failed", "relay", relayURL, "repo_id", mapping.RepoID, "error", err)
			continue
		}
		for _, ev := range events {
			if !stateEventMatchesMapping(ev, mapping) {
				continue
			}
			if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
				continue
			}
			if latest == nil || ev.CreatedAt > latest.CreatedAt {
				latest = cloneEvent(ev)
			}
		}
	}
	return latest
}

func (s *Service) fetchPREvents(ctx context.Context, mapping store.Mapping, relayURLs []string) []*nostr.Event {
	coord := repoCoordinate(mapping)
	filter := nostr.Filter{
		Kinds: []nostr.Kind{relay.KindPROpen, relay.KindPRUpdate},
		Tags:  nostr.TagMap{"a": []string{coord}},
		Limit: prQueryLimit,
	}
	seen := map[string]bool{}
	var out []*nostr.Event
	for _, relayURL := range relayURLs {
		events, err := s.queryRelayHistory(ctx, relayURL, filter, prQueryLimit)
		if err != nil {
			s.logger.Warn("proactive sync PR relay query failed", "relay", relayURL, "repo_id", mapping.RepoID, "error", err)
			continue
		}
		for _, ev := range events {
			if !prEventMatchesRepo(ev, coord) || seen[ev.ID.Hex()] {
				continue
			}
			if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
				continue
			}
			seen[ev.ID.Hex()] = true
			out = append(out, cloneEvent(ev))
		}
	}
	return out
}

func (s *Service) queryRelayHistory(ctx context.Context, relayURL string, base nostr.Filter, pageLimit int) ([]*nostr.Event, error) {
	if pageLimit <= 0 {
		pageLimit = 100
	}
	var all []*nostr.Event
	var until nostr.Timestamp // 0 means no upper bound
	for {
		filter := base.Clone()
		filter.Limit = pageLimit
		filter.Until = until
		events, err := s.queryRelay(ctx, relayURL, filter)
		if err != nil {
			if len(all) > 0 {
				return all, nil
			}
			return nil, err
		}
		if len(events) == 0 {
			break
		}
		all = append(all, events...)
		if len(events) < pageLimit {
			break
		}
		var oldest nostr.Timestamp
		for _, ev := range events {
			if ev == nil {
				continue
			}
			if oldest == 0 || ev.CreatedAt < oldest {
				oldest = ev.CreatedAt
			}
		}
		if oldest <= 0 || (until != 0 && oldest >= until) {
			break
		}
		until = oldest - 1
	}
	return all, nil
}

func (s *Service) fetchMissingStateObjects(ctx context.Context, repoPath string, cloneURLs []string, state nip34.RepositoryState) error {
	missing := uniqueStateSHAs(ctx, s.git, repoPath, state)
	if len(missing) == 0 || len(cloneURLs) == 0 {
		return nil
	}
	var errs []string
	for _, cloneURL := range cloneURLs {
		if err := s.git.Fetch(ctx, repoPath, cloneURL, missing); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return nil
	}
	return fmt.Errorf("all clone fetches failed: %s", strings.Join(errs, "; "))
}

func (s *Service) fetchPRTip(ctx context.Context, repoPath string, ev *nostr.Event) error {
	if ev == nil || !validNostrEventID.MatchString(ev.ID.Hex()) {
		return nil
	}
	tipSHA := tagValue(ev.Tags, "c")
	if !validHex.MatchString(tipSHA) {
		return nil
	}
	cloneURLs := tagValues(ev.Tags, "clone")
	if len(cloneURLs) == 0 {
		return nil
	}
	ref := "refs/nostr/" + ev.ID.Hex()
	refspec := "+" + tipSHA + ":" + ref
	var errs []string
	for _, cloneURL := range cloneURLs {
		if err := s.git.Fetch(ctx, repoPath, cloneURL, []string{refspec}); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return nil
	}
	return fmt.Errorf("all PR clone fetches failed: %s", strings.Join(errs, "; "))
}

func (s *Service) applyStateEvent(ctx context.Context, repoPath string, ev *nostr.Event) error {
	state := nip34.ParseRepositoryState(*ev)
	for branch, sha := range state.Branches {
		ref := "refs/heads/" + branch
		if !validRef.MatchString(ref) || !validHex.MatchString(sha) {
			s.logger.Warn("proactive sync skipped invalid ref or sha", "repo", repoPath, "ref", ref, "sha", sha)
			continue
		}
		if err := s.updateRefIfObjectExists(ctx, repoPath, ref, sha); err != nil {
			s.logger.Warn("proactive sync branch update failed", "repo", repoPath, "ref", branch, "error", err)
		}
	}
	for tag, sha := range state.Tags {
		if strings.HasSuffix(tag, "^{}") {
			continue
		}
		ref := "refs/tags/" + tag
		if !validRef.MatchString(ref) || !validHex.MatchString(sha) {
			s.logger.Warn("proactive sync skipped invalid ref or sha", "repo", repoPath, "ref", ref, "sha", sha)
			continue
		}
		if err := s.updateRefIfObjectExists(ctx, repoPath, ref, sha); err != nil {
			s.logger.Warn("proactive sync tag update failed", "repo", repoPath, "ref", tag, "error", err)
		}
	}

	s.reconcileHEAD(ctx, repoPath, state)
	s.reconcileDeletedRefs(ctx, repoPath, state)

	s.logger.Info("proactive sync applied state event", "repo", repoPath, "event", ev.ID.Hex())
	return nil
}

// reconcileDeletedRefs removes local refs/heads/* and refs/tags/* that the
// authoritative signed state no longer declares. Repository state represents
// deletion by omission, so a ref present locally but absent from the latest
// state has been deleted upstream. Other namespaces (refs/nostr, refs/pull,
// internal refs) are never touched.
func (s *Service) reconcileDeletedRefs(ctx context.Context, repoPath string, state nip34.RepositoryState) {
	prune := func(prefix string, declared func(name string) bool) {
		refs, err := s.git.ListRefs(ctx, repoPath, prefix)
		if err != nil {
			s.logger.Warn("proactive sync ref listing failed", "repo", repoPath, "prefix", prefix, "error", err)
			return
		}
		for _, ref := range refs {
			name := strings.TrimPrefix(ref, prefix)
			if name == "" || declared(name) {
				continue
			}
			if err := s.git.DeleteRef(ctx, repoPath, ref); err != nil {
				s.logger.Warn("proactive sync ref deletion failed", "repo", repoPath, "ref", ref, "error", err)
				continue
			}
			s.logger.Info("proactive sync deleted ref omitted from state", "repo", repoPath, "ref", ref)
		}
	}
	prune("refs/heads/", func(name string) bool {
		_, ok := state.Branches[name]
		return ok
	})
	prune("refs/tags/", func(name string) bool {
		if _, ok := state.Tags[name]; ok {
			return true
		}
		_, ok := state.Tags[name+"^{}"]
		return ok
	})
}

// reconcileHEAD updates the bare repository's symbolic HEAD to match the
// state event's HEAD tag. The target must name a branch the state declares
// (refs/heads/*), pass ref validation, and point at an object that exists
// locally — otherwise HEAD is left untouched.
func (s *Service) reconcileHEAD(ctx context.Context, repoPath string, state nip34.RepositoryState) {
	branch := strings.TrimSpace(state.HEAD)
	if branch == "" {
		return
	}
	ref := "refs/heads/" + branch
	if !validRef.MatchString(ref) {
		s.logger.Warn("proactive sync skipped invalid HEAD target", "repo", repoPath, "head", branch)
		return
	}
	sha, declared := state.Branches[branch]
	if !declared {
		s.logger.Warn("proactive sync HEAD names undeclared branch", "repo", repoPath, "head", branch)
		return
	}
	if !validHex.MatchString(sha) {
		s.logger.Warn("proactive sync HEAD branch has invalid sha", "repo", repoPath, "head", branch, "sha", sha)
		return
	}
	exists, err := s.git.ObjectExists(ctx, repoPath, sha)
	if err != nil || !exists {
		s.logger.Warn("proactive sync HEAD target object missing", "repo", repoPath, "head", branch, "sha", sha, "error", err)
		return
	}
	if err := s.git.SetSymbolicHEAD(ctx, repoPath, ref); err != nil {
		s.logger.Warn("proactive sync HEAD update failed", "repo", repoPath, "head", branch, "error", err)
	}
}

func (s *Service) updateRefIfObjectExists(ctx context.Context, repoPath string, ref string, sha string) error {
	exists, err := s.git.ObjectExists(ctx, repoPath, sha)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("object %s not present locally", sha)
	}
	return s.git.UpdateRef(ctx, repoPath, ref, sha)
}

func cachedAnnouncement(mapping store.Mapping) (*nostr.Event, error) {
	if strings.TrimSpace(mapping.AnnouncementEventJSON) == "" {
		return nil, nil
	}
	var ev nostr.Event
	if err := json.Unmarshal([]byte(mapping.AnnouncementEventJSON), &ev); err != nil {
		return nil, fmt.Errorf("decode cached announcement event: %w", err)
	}
	if ev.Kind != relay.KindRepositoryAnnouncement {
		return nil, nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(&ev); err != nil {
		return nil, fmt.Errorf("cached announcement signature invalid: %w", err)
	}
	if ev.PubKey.Hex() != mapping.Pubkey {
		return nil, fmt.Errorf("cached announcement pubkey %s does not match mapping pubkey %s", ev.PubKey.Hex(), mapping.Pubkey)
	}
	if tagValue(ev.Tags, "d") != mapping.RepoID {
		return nil, fmt.Errorf("cached announcement d tag does not match repo id %s", mapping.RepoID)
	}
	return &ev, nil
}

func announcementCloneURLs(mapping store.Mapping, announcement *nostr.Event) []string {
	var urls []string
	if announcement != nil {
		urls = append(urls, tagValues(announcement.Tags, "clone")...)
	}
	if mapping.AnnouncedCloneURL != "" {
		urls = append(urls, mapping.AnnouncedCloneURL)
	}
	return uniqueNonEmpty(urls)
}

func announcementRelayURLs(announcement *nostr.Event) []string {
	if announcement == nil {
		return nil
	}
	var urls []string
	for _, tag := range announcement.Tags {
		if len(tag) < 2 || tag[0] != "relays" {
			continue
		}
		urls = append(urls, tag[1:]...)
	}
	return uniqueNonEmpty(urls)
}

func uniqueStateSHAs(ctx context.Context, git gitRunner, repoPath string, state nip34.RepositoryState) []string {
	seen := map[string]bool{}
	var out []string
	add := func(sha string) {
		if !validHex.MatchString(sha) || seen[sha] {
			return
		}
		seen[sha] = true
		exists, err := git.ObjectExists(ctx, repoPath, sha)
		if err == nil && !exists {
			out = append(out, sha)
		}
	}
	for _, sha := range state.Branches {
		add(sha)
	}
	for tag, sha := range state.Tags {
		if strings.HasSuffix(tag, "^{}") {
			continue
		}
		add(sha)
	}
	return out
}

func stateEventMatchesMapping(ev *nostr.Event, mapping store.Mapping) bool {
	if ev == nil || ev.Kind != relay.KindRepositoryState {
		return false
	}
	if tagValue(ev.Tags, "d") != mapping.RepoID {
		return false
	}
	return ev.PubKey.Hex() == mapping.Pubkey
}

func prEventMatchesRepo(ev *nostr.Event, coord string) bool {
	if ev == nil || (ev.Kind != relay.KindPROpen && ev.Kind != relay.KindPRUpdate) {
		return false
	}
	return tagValue(ev.Tags, "a") == coord && tagValue(ev.Tags, "c") != "" && len(tagValues(ev.Tags, "clone")) > 0
}

func repoCoordinate(mapping store.Mapping) string {
	return fmt.Sprintf("%d:%s:%s", relay.KindRepositoryAnnouncement, mapping.Pubkey, mapping.RepoID)
}

func repoPathForMapping(repositoriesDir string, mapping store.Mapping) string {
	repoName := mapping.RepoName
	if repoName == "" {
		repoName = mapping.RepoID
	}
	return filepath.Join(repositoriesDir, mapping.Owner, repoName+".git")
}

func tagValue(tags nostr.Tags, key string) string {
	v := tags.Find(key)
	if v == nil || len(v) < 2 {
		return ""
	}
	return v[1]
}

func tagValues(tags nostr.Tags, key string) []string {
	var out []string
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			out = append(out, tag[1])
		}
	}
	return uniqueNonEmpty(out)
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(strings.TrimRight(v, "/"))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func cloneEvent(ev *nostr.Event) *nostr.Event {
	if ev == nil {
		return nil
	}
	copy := *ev
	copy.Tags = append(nostr.Tags{}, ev.Tags...)
	return &copy
}

type execGitRunner struct{}

func (execGitRunner) ObjectExists(ctx context.Context, repoPath string, sha string) (bool, error) {
	if err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "cat-file", "-e", sha).Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, nil
	}
	return true, nil
}

func (execGitRunner) UpdateRef(ctx context.Context, repoPath string, ref string, sha string) error {
	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "update-ref", ref, sha).CombinedOutput(); err != nil {
		return fmt.Errorf("update-ref failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (execGitRunner) ListRefs(ctx context.Context, repoPath string, prefix string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "for-each-ref", "--format=%(refname)", prefix).Output()
	if err != nil {
		return nil, fmt.Errorf("for-each-ref failed: %w", err)
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			refs = append(refs, line)
		}
	}
	return refs, nil
}

func (execGitRunner) DeleteRef(ctx context.Context, repoPath string, ref string) error {
	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "update-ref", "-d", ref).CombinedOutput(); err != nil {
		return fmt.Errorf("update-ref -d failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (execGitRunner) SetSymbolicHEAD(ctx context.Context, repoPath string, ref string) error {
	if out, err := exec.CommandContext(ctx, "git", "--git-dir", repoPath, "symbolic-ref", "HEAD", ref).CombinedOutput(); err != nil {
		return fmt.Errorf("symbolic-ref HEAD failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (execGitRunner) Fetch(ctx context.Context, repoPath string, remoteURL string, refspecs []string) error {
	if len(refspecs) == 0 {
		return nil
	}
	args := []string{"--git-dir", repoPath, "fetch", "--no-tags", remoteURL}
	args = append(args, refspecs...)
	if out, err := exec.CommandContext(ctx, "git", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("git fetch failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func queryRelaySync(ctx context.Context, relayURL string, filter nostr.Filter) ([]*nostr.Event, error) {
	qCtx, cancel := context.WithTimeout(ctx, relayQueryTimeout)
	defer cancel()
	r, err := nostr.RelayConnect(qCtx, relayURL, nostr.RelayOptions{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var events []*nostr.Event
	for ev := range r.QueryEvents(filter) {
		e := ev
		events = append(events, &e)
	}
	return events, nil
}

package loom

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
	"github.com/sharegap/grasp-gitea/internal/relay"
)

const defaultWorkerAdTTL = 15 * time.Minute

// WorkerPoolConfig defines the trusted-fleet worker advertisement cache.
type WorkerPoolConfig struct {
	Allowlist        []string
	RequiredSoftware []string
	AdTTL            time.Duration
	FutureSkew       time.Duration
}

// WorkerAd is the canonical latest allowlisted advertisement for a worker.
type WorkerAd struct {
	Event           nostr.Event
	Software        map[string]string
	MinDuration     time.Duration
	MaxDuration     time.Duration
	RequiresPayment bool
}

// WorkerPool keeps at most one canonical kind-10100 event per allowlisted key.
type WorkerPool struct {
	mu               sync.Mutex
	allowlist        map[string]struct{}
	requiredSoftware []string
	adTTL            time.Duration
	futureSkew       time.Duration
	ads              map[string]nostr.Event
}

func NewWorkerPool(cfg WorkerPoolConfig) *WorkerPool {
	allowlist := make(map[string]struct{}, len(cfg.Allowlist))
	for _, raw := range cfg.Allowlist {
		if pk, err := nostr.PubKeyFromHex(strings.TrimSpace(raw)); err == nil {
			allowlist[pk.Hex()] = struct{}{}
		}
	}
	required := make([]string, 0, len(cfg.RequiredSoftware))
	for _, software := range cfg.RequiredSoftware {
		if software = strings.ToLower(strings.TrimSpace(software)); software != "" {
			required = append(required, software)
		}
	}
	if len(required) == 0 {
		required = []string{"act"}
	}
	if cfg.AdTTL <= 0 {
		cfg.AdTTL = defaultWorkerAdTTL
	}
	if cfg.FutureSkew <= 0 {
		cfg.FutureSkew = defaultFutureSkew
	}
	return &WorkerPool{
		allowlist: allowlist, requiredSoftware: required, adTTL: cfg.AdTTL,
		futureSkew: cfg.FutureSkew, ads: make(map[string]nostr.Event),
	}
}

// HandleEvent verifies and caches the canonical latest ad for an allowlisted author.
func (p *WorkerPool) HandleEvent(ev *nostr.Event, now time.Time) error {
	if p == nil || ev == nil || ev.Kind != relay.KindLoomWorkerAd {
		return nil
	}
	if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
		return fmt.Errorf("invalid worker advertisement: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if time.Unix(int64(ev.CreatedAt), 0).After(now.Add(p.futureSkew)) {
		return fmt.Errorf("worker advertisement exceeds future-skew guard")
	}
	author := ev.PubKey.Hex()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.allowlist[author]; !ok {
		return nil
	}
	current, ok := p.ads[author]
	if ok && !canonicalNewer(*ev, current) {
		return nil
	}
	copyEvent := *ev
	copyEvent.Tags = cloneTags(ev.Tags)
	p.ads[author] = copyEvent
	return nil
}

// Select returns the deterministic best eligible worker. Canonical replacement
// is resolved before capability validation, so a newer malformed ad cannot leave
// an older, now-superseded offer selectable.
func (p *WorkerPool) Select(now time.Time, jobBound time.Duration, paymentConfigured bool) (WorkerAd, bool) {
	if p == nil {
		return WorkerAd{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var selected WorkerAd
	found := false
	for author, ev := range p.ads {
		created := time.Unix(int64(ev.CreatedAt), 0)
		if created.Before(now.Add(-p.adTTL)) {
			delete(p.ads, author)
			continue
		}
		ad, err := parseWorkerAd(ev)
		if err != nil || !p.eligible(ad, jobBound, paymentConfigured) {
			continue
		}
		if !found || canonicalNewer(ad.Event, selected.Event) ||
			(ad.Event.CreatedAt == selected.Event.CreatedAt && ad.Event.ID == selected.Event.ID &&
				ad.Event.PubKey.Hex() < selected.Event.PubKey.Hex()) {
			selected, found = ad, true
		}
	}
	return selected, found
}

func (p *WorkerPool) eligible(ad WorkerAd, jobBound time.Duration, paymentConfigured bool) bool {
	for _, required := range p.requiredSoftware {
		if _, ok := ad.Software[required]; !ok {
			return false
		}
	}
	if jobBound <= 0 {
		return false
	}
	if ad.MinDuration > jobBound || ad.MaxDuration < jobBound {
		return false
	}
	if ad.RequiresPayment && !paymentConfigured {
		return false
	}
	return true
}

func parseWorkerAd(ev nostr.Event) (WorkerAd, error) {
	ad := WorkerAd{Event: ev, Software: map[string]string{}}
	var minSet, maxSet bool
	for _, tag := range ev.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "S":
			name := strings.ToLower(strings.TrimSpace(tag[1]))
			if name == "" {
				return WorkerAd{}, fmt.Errorf("empty worker software name")
			}
			version := ""
			if len(tag) >= 3 {
				version = strings.TrimSpace(tag[2])
			}
			ad.Software[name] = version
		case "min_duration", "max_duration":
			seconds, err := strconv.ParseInt(strings.TrimSpace(tag[1]), 10, 64)
			if err != nil || seconds < 0 {
				return WorkerAd{}, fmt.Errorf("invalid %s", tag[0])
			}
			duration := time.Duration(seconds) * time.Second
			if tag[0] == "min_duration" {
				ad.MinDuration, minSet = duration, true
			} else {
				ad.MaxDuration, maxSet = duration, true
			}
		case "price":
			if len(tag) < 4 {
				return WorkerAd{}, fmt.Errorf("malformed worker price")
			}
			price, err := strconv.ParseFloat(strings.TrimSpace(tag[2]), 64)
			if err != nil || price < 0 {
				return WorkerAd{}, fmt.Errorf("invalid worker price")
			}
			if price > 0 {
				ad.RequiresPayment = true
			}
		}
	}
	if !minSet || !maxSet || ad.MaxDuration <= 0 || ad.MinDuration > ad.MaxDuration {
		return WorkerAd{}, fmt.Errorf("invalid worker duration bounds")
	}
	return ad, nil
}

func canonicalNewer(candidate, current nostr.Event) bool {
	if candidate.CreatedAt != current.CreatedAt {
		return candidate.CreatedAt > current.CreatedAt
	}
	return candidate.ID.Hex() < current.ID.Hex()
}

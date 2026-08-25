package loom

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/cashu"
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
	MaxJobs         int
	QueueDepth      int
	RequiresPayment bool
	TrustedUnpaid   bool
	Prices          map[string]uint64
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
	return p.selectWorker(now, jobBound, paymentConfigured, "")
}

// SelectForMint returns the lowest-priced eligible worker advertising the
// configured Cashu mint. Canonical event ordering breaks equal-price ties.
func (p *WorkerPool) SelectForMint(now time.Time, jobBound time.Duration, mintURL string) (WorkerAd, bool) {
	normalized, err := cashu.NormalizeMintURL(mintURL)
	if err != nil {
		return WorkerAd{}, false
	}
	return p.selectWorker(now, jobBound, true, normalized)
}

func (p *WorkerPool) selectWorker(now time.Time, jobBound time.Duration, paymentConfigured bool, mintURL string) (WorkerAd, bool) {
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
		if mintURL != "" {
			price, supported := ad.Prices[mintURL]
			if !supported || price == 0 {
				continue
			}
		}
		selectedPrice, candidatePrice := uint64(0), uint64(0)
		if mintURL != "" {
			selectedPrice, candidatePrice = selected.Prices[mintURL], ad.Prices[mintURL]
		}
		if !found || (mintURL != "" && candidatePrice < selectedPrice) ||
			(candidatePrice == selectedPrice && canonicalNewer(ad.Event, selected.Event)) ||
			(candidatePrice == selectedPrice && ad.Event.CreatedAt == selected.Event.CreatedAt &&
				ad.Event.ID == selected.Event.ID && ad.Event.PubKey.Hex() < selected.Event.PubKey.Hex()) {
			selected, found = ad, true
			continue
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
	if ad.MaxJobs > 0 && ad.QueueDepth >= ad.MaxJobs {
		return false
	}
	if ad.RequiresPayment && !paymentConfigured && !ad.TrustedUnpaid {
		return false
	}
	return true
}

func parseWorkerAd(ev nostr.Event) (WorkerAd, error) {
	ad := WorkerAd{Event: ev, Software: map[string]string{}, Prices: map[string]uint64{}}
	ad.TrustedUnpaid = workerAdHasFeature(ev.Content, "trusted_unpaid_internal_jobs")
	ad.MaxJobs, ad.QueueDepth = workerAdQueue(ev.Content)
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
			mintRaw, priceRaw, unitRaw, err := workerPriceTag(tag)
			if err != nil {
				return WorkerAd{}, fmt.Errorf("malformed worker price")
			}
			mintURL, err := cashu.NormalizeMintURL(mintRaw)
			if err != nil || !strings.EqualFold(strings.TrimSpace(unitRaw), "sat") {
				return WorkerAd{}, fmt.Errorf("invalid worker price mint/unit")
			}
			price, err := parseAdvertisedPrice(priceRaw)
			if err != nil {
				return WorkerAd{}, fmt.Errorf("invalid worker price")
			}
			if old, ok := ad.Prices[mintURL]; !ok || price < old {
				ad.Prices[mintURL] = price
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

func workerPriceTag(tag nostr.Tag) (mintURL, price, unit string, err error) {
	if len(tag) >= 5 && strings.EqualFold(strings.TrimSpace(tag[1]), "cashu") {
		return tag[4], tag[2], tag[3], nil
	}
	if len(tag) >= 4 {
		return tag[1], tag[2], tag[3], nil
	}
	return "", "", "", fmt.Errorf("too few fields")
}

func parseAdvertisedPrice(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty price")
	}
	if !strings.ContainsAny(raw, ".eE") {
		return strconv.ParseUint(raw, 10, 64)
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("invalid decimal price")
	}
	if value == 0 {
		return 0, nil
	}
	if value > float64(^uint64(0)) {
		return 0, fmt.Errorf("decimal price overflows uint64")
	}
	// Cashu tokens are integer sats; round fractional sat/sec advertisements up
	// if a future paid dispatcher uses this path. Trusted mode only uses the
	// non-zero price as a payment-required signal.
	return uint64(math.Ceil(value)), nil
}

func workerAdHasFeature(content, feature string) bool {
	var payload struct {
		Capabilities struct {
			Features []string `json:"features"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return false
	}
	for _, candidate := range payload.Capabilities.Features {
		if strings.EqualFold(strings.TrimSpace(candidate), feature) {
			return true
		}
	}
	return false
}

func workerAdQueue(content string) (maxJobs, queueDepth int) {
	var payload struct {
		MaxConcurrentJobs int `json:"max_concurrent_jobs"`
		CurrentQueueDepth int `json:"current_queue_depth"`
	}
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return 0, 0
	}
	if payload.MaxConcurrentJobs < 0 {
		payload.MaxConcurrentJobs = 0
	}
	if payload.CurrentQueueDepth < 0 {
		payload.CurrentQueueDepth = 0
	}
	return payload.MaxConcurrentJobs, payload.CurrentQueueDepth
}

func canonicalNewer(candidate, current nostr.Event) bool {
	if candidate.CreatedAt != current.CreatedAt {
		return candidate.CreatedAt > current.CreatedAt
	}
	return candidate.ID.Hex() < current.ID.Hex()
}

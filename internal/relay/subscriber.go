package relay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Handler processes a nostr event received from a relay subscription.
type Handler func(ctx context.Context, ev *nostr.Event, relayURL string) error

// Subscriber manages persistent WebSocket subscriptions to nostr relays
// and dispatches received events to a Handler.
type Subscriber struct {
	relays  []string
	handler Handler
	logger  *slog.Logger
	wg      sync.WaitGroup
}

// New creates a Subscriber that will connect to the given relay URLs.
func New(relays []string, handler Handler, logger *slog.Logger) *Subscriber {
	return &Subscriber{relays: relays, handler: handler, logger: logger}
}

// Run starts a goroutine per relay and returns immediately.
// Call Wait() after context cancellation to ensure clean shutdown.
func (s *Subscriber) Run(ctx context.Context) {
	for _, relayURL := range s.relays {
		s.wg.Add(1)
		go func(url string) {
			defer s.wg.Done()
			s.watchRelay(ctx, url)
		}(relayURL)
	}
}

// Wait blocks until all subscriber goroutines have exited.
func (s *Subscriber) Wait() {
	s.wg.Wait()
}

func (s *Subscriber) watchRelay(ctx context.Context, relayURL string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			s.logger.Error("failed to connect relay", "relay", relayURL, "error", err)
			sleepOrDone(ctx, 3*time.Second)
			continue
		}

		sub, err := relay.Subscribe(ctx, []nostr.Filter{{Kinds: []int{KindRepositoryAnnouncement, KindRepositoryState}}})
		if err != nil {
			s.logger.Error("failed to subscribe relay", "relay", relayURL, "error", err)
			relay.Close()
			sleepOrDone(ctx, 3*time.Second)
			continue
		}

		s.logger.Info("subscribed to relay", "relay", relayURL)
		func() {
			defer relay.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-sub.Events:
					if !ok {
						s.logger.Warn("relay event stream closed", "relay", relayURL)
						sleepOrDone(ctx, 2*time.Second)
						return
					}
					if ev == nil {
						continue
					}
					if err := s.handler(ctx, ev, relayURL); err != nil {
						s.logger.Warn("announcement handling failed", "relay", relayURL, "event", ev.ID, "error", err)
					}
				}
			}
		}()
	}
}

func sleepOrDone(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
		return
	}
}

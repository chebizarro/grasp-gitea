package relay

import (
	"context"
	"log/slog"
	"time"

	"github.com/nbd-wtf/go-nostr"
)


type Handler func(ctx context.Context, ev *nostr.Event, relayURL string) error

type Subscriber struct {
	relays  []string
	handler Handler
	logger  *slog.Logger
}

func New(relays []string, handler Handler, logger *slog.Logger) *Subscriber {
	return &Subscriber{relays: relays, handler: handler, logger: logger}
}

func (s *Subscriber) Run(ctx context.Context) {
	for _, relayURL := range s.relays {
		go s.watchRelay(ctx, relayURL)
	}
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
			sleepOrDone(ctx, 3*time.Second)
			continue
		}

		s.logger.Info("subscribed to relay", "relay", relayURL)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.Events:
				if !ok {
					s.logger.Warn("relay event stream closed", "relay", relayURL)
					sleepOrDone(ctx, 2*time.Second)
					goto reconnect
				}
				if ev == nil {
					continue
				}
				if err := s.handler(ctx, ev, relayURL); err != nil {
					s.logger.Warn("announcement handling failed", "relay", relayURL, "event", ev.ID, "error", err)
				}
			}
		}

	reconnect:
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

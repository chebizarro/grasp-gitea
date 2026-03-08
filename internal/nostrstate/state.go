package nostrstate

import (
	"context"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip34"

	"github.com/sharegap/grasp-gitea/internal/nostrverify"
)

func FetchLatestRepositoryStateForRepo(ctx context.Context, relayURL string, ownerPubkey string, repoID string) (*nostr.Event, *nip34.RepositoryState, []string, error) {
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect relay: %w", err)
	}

	filter := nostr.Filter{
		Kinds: []int{nostr.KindRepositoryAnnouncement, nostr.KindRepositoryState},
		Tags: nostr.TagMap{
			"d": []string{repoID},
		},
	}

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sub, err := relay.Subscribe(subCtx, []nostr.Filter{filter})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("subscribe relay: %w", err)
	}
	go func() {
		<-sub.EndOfStoredEvents
		cancel()
	}()

	var events []nostr.Event
	for ev := range sub.Events {
		if ev == nil {
			continue
		}
		if err := nostrverify.ValidateEventIDAndSignature(ev); err != nil {
			continue
		}
		repo := nip34.ParseRepository(*ev)
		if repo.ID != repoID {
			continue
		}
		events = append(events, *ev)
	}

	maintainers, err := extractMaintainers(events, ownerPubkey, repoID)
	if err != nil {
		return nil, nil, nil, err
	}

	maintainerSet := map[string]struct{}{}
	for _, m := range maintainers {
		maintainerSet[m] = struct{}{}
	}

	var latest *nostr.Event
	for i := range events {
		ev := events[i]
		if ev.Kind != nostr.KindRepositoryState {
			continue
		}
		if _, ok := maintainerSet[ev.PubKey]; !ok {
			continue
		}
		if latest == nil || ev.CreatedAt > latest.CreatedAt {
			copy := ev
			latest = &copy
		}
	}

	if latest == nil {
		return nil, nil, nil, fmt.Errorf("no repository state event found")
	}

	state := nip34.ParseRepositoryState(*latest)
	return latest, &state, maintainers, nil
}

func extractMaintainers(events []nostr.Event, ownerPubkey string, repoID string) ([]string, error) {
	announcementsByPubkey := map[string]nostr.Event{}
	for _, ev := range events {
		if ev.Kind != nostr.KindRepositoryAnnouncement {
			continue
		}
		repo := nip34.ParseRepository(ev)
		if repo.ID != repoID {
			continue
		}
		announcementsByPubkey[ev.PubKey] = ev
	}

	if _, ok := announcementsByPubkey[ownerPubkey]; !ok {
		return nil, fmt.Errorf("owner repository announcement not found")
	}

	seen := map[string]struct{}{}
	var ordered []string
	var visit func(string)
	visit = func(pubkey string) {
		if _, ok := seen[pubkey]; ok {
			return
		}
		seen[pubkey] = struct{}{}
		ordered = append(ordered, pubkey)

		ann, ok := announcementsByPubkey[pubkey]
		if !ok {
			return
		}
		repo := nip34.ParseRepository(ann)
		for _, maintainer := range repo.Maintainers {
			visit(maintainer)
		}
	}

	visit(ownerPubkey)
	return ordered, nil
}
